/* TST-005 정탐 시험용 취약 C 샘플 — 의도적으로 취약하게 작성된 코드다 (SFR-011).
 *
 * 컴파일·실행하거나 참고용으로 복사하지 말 것. catalog/rules/c_*.yaml의 KISA 룰
 * 13개가 각각 정확히 걸리는지 확인하는 고정 자산이며, 안전한 대응 코드는 safe.c에
 * 있다. 기대 건수는 catalog/tests.py EXPECTED_C_SAMPLE_FINDINGS.
 *
 * 우리 SAST로 우리 코드를 분석할 때(도그푸딩·CI 게이트) 당연히 탐지된다 —
 * 분석 대상에서 catalog/samples/를 제외하고 돌려야 한다.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

struct node {
    int value;
    struct node *next;
};

/* ---- KISA-SF-06 하드코드된 중요정보 (2건) ---------------------------------- */

#define ADMIN_PASSWORD "s3cret!"               /* SF-06 #1 */
static const char *db_password = "hunter2";    /* SF-06 #2 */

/* ---- KISA-SF-13 주석 속 비밀 (1건) ---------------------------------------- */

// 운영 DB: api_key = AKIA0123456789EXAMPLE   /* SF-13 */

/* ---- KISA-IV-16 메모리 버퍼 오버플로우 (5건) ------------------------------- */

void copy_input(char *src)
{
    char buf[16];
    char line[64];

    gets(line);                               /* IV-16 #1 */
    strcpy(buf, src);                         /* IV-16 #2 */
    strcat(buf, src);                         /* IV-16 #3 */
    sprintf(buf, "%s-%s", src, src);          /* IV-16 #4 */
    scanf("%s", buf);                         /* IV-16 #5 — 폭 없는 %s */
}

/* ---- KISA-IV-17 포맷 스트링 삽입 (3건) ------------------------------------- */

void log_message(char *msg)
{
    char out[64];

    printf(msg);                              /* IV-17 #1 */
    fprintf(stderr, msg);                     /* IV-17 #2 */
    snprintf(out, sizeof out, msg);           /* IV-17 #3 */
}

/* ---- KISA-IV-05 운영체제 명령어 삽입 (2건) --------------------------------- */

void ping_host(char *host)
{
    char cmd[128];

    snprintf(cmd, sizeof cmd, "ping -c 1 %s", host);
    system(cmd);                              /* IV-05 #1 */
    FILE *p = popen(cmd, "r");                /* IV-05 #2 */
    pclose(p);
}

/* ---- KISA-CE-03 해제된 자원 사용 (3건) ------------------------------------- */

void use_after_free(struct node *n)
{
    free(n);
    n->value = 1;                             /* CE-03 #1 — 역참조 */
}

void double_free(char *p)
{
    free(p);
    free(p);                                  /* CE-03 #2 — 이중 해제 */
}

void pass_freed(char *p)
{
    free(p);
    puts(p);                                  /* CE-03 #3 — 함수 인자로 전달 */
}

/* ---- KISA-TS-01 TOCTOU (2건) --------------------------------------------- */

void write_if_allowed(const char *path)
{
    if (access(path, W_OK) == 0) {            /* TS-01 #1 — 검사 후 열기 */
        FILE *f = fopen(path, "w");
        if (f) fclose(f);
    }
}

void read_after_stat(const char *path)
{
    struct stat st;

    stat(path, &st);                          /* TS-01 #2 */
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

/* ---- KISA-CE-02 부적절한 자원 해제 (1건) ----------------------------------- */

int first_byte(const char *path)
{
    FILE *f = fopen(path, "r");               /* CE-02 — fclose 없음 */
    if (!f) return -1;
    return fgetc(f);
}

/* ---- KISA-CE-01 Null Pointer 역참조 (2건) ---------------------------------- */

struct node *make_node(void)
{
    struct node *n = malloc(sizeof *n);
    n->value = 0;                             /* CE-01 #1 — 할당 직후 역참조 */
    return n;
}

void read_header(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");
    fgets(buf, (int)n, f);                    /* CE-01 #2 — 열기 직후 사용 */
    fclose(f);
}

/* ---- KISA-SF-03 잘못된 권한 설정 (4건) ------------------------------------- */

void create_config(const char *path)
{
    chmod(path, 0777);                                       /* SF-03 #1 */
    int fd = open(path, O_CREAT | O_WRONLY, 0666);           /* SF-03 #2 */
    close(fd);
    mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);                /* SF-03 #3 */
    umask(0);                                                /* SF-03 #4 */
}

/* ---- KISA-SF-08 부적절한 난수 (2건) ---------------------------------------- */

void make_session(char *token, size_t n)
{
    srand((unsigned)time(NULL));
    int session_id = rand();                                 /* SF-08 #1 */
    for (size_t i = 0; i < n; i++)
        token[i] = rand() % 26 + 'a';                        /* SF-08 #2 */
    (void)session_id;
}

/* ---- KISA-SF-04 취약한 암호화 알고리즘 (2건) ------------------------------- */

void hash_password(const unsigned char *pw, size_t n, unsigned char *out)
{
    MD5(pw, n, out);                                         /* SF-04 #1 */
}

void encrypt_block(DES_key_schedule *ks, DES_cblock *in, DES_cblock *out)
{
    DES_ecb_encrypt(in, out, ks, DES_ENCRYPT);               /* SF-04 #2 */
}

/* ---- KISA-AA-02 취약한 API (2건) ------------------------------------------- */

void make_temp(void)
{
    char tmpl[] = "/tmp/appXXXXXX";

    char *name = tmpnam(NULL);                               /* AA-02 #1 */
    mktemp(tmpl);                                            /* AA-02 #2 */
    (void)name;
}
