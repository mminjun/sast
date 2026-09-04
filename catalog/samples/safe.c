/* TST-005 오탐 시험용 안전 C 샘플 — vulnerable.c의 각 취약점에 대한 올바른 대응 (SFR-011).
 *
 * 여기서 findings가 하나라도 나오면 룰이 과탐지하는 것이다(오탐). 정탐 못지않게
 * 중요한 기준이라 취약 샘플과 짝으로 유지한다. CE-01의 "몇 줄 뒤에 오는 검사"
 * (assert, 헬퍼 함수)가 오탐이 되지 않는지도 여기서 실측한다.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

struct node {
    int value;
    struct node *next;
};

struct app {
    FILE *log;
};

/* ---- SF-06 대응: 값은 환경변수·설정에서, 소스에는 위치만 ---------------------- */

#define DB_CREDENTIAL_ENV "APP_DB_PASSWORD"       /* 환경변수 이름이지 값이 아님 */
#define API_TOKEN ""                              /* 빈 값 자리표시자 */
static const char *greeting = "hello";

const char *db_password(void)
{
    return getenv(DB_CREDENTIAL_ENV);
}

/* ---- SF-13 대응: 주석에는 값 없이 위치만 ------------------------------------ */

// 운영 DB 비밀번호는 시크릿 저장소 APP_DB_PASSWORD 항목에 있다 (값을 여기 적지 말 것)

/* ---- IV-16 대응: 길이를 받는 함수 -------------------------------------------- */

void copy_input(const char *src)
{
    char buf[16];
    char line[64];

    if (fgets(line, sizeof line, stdin) == NULL) return;
    strncpy(buf, src, sizeof buf - 1);
    buf[sizeof buf - 1] = '\0';
    snprintf(buf, sizeof buf, "%s-%s", src, src);
    scanf("%15s", buf);
    scanf("%d items", &line[0]);                  /* 폭 없는 %s가 아니라 %d */
}

/* ---- IV-17 대응: 포맷은 상수, 값은 인자 -------------------------------------- */

void log_message(const char *msg)
{
    char out[64];

    printf("%s", msg);
    fprintf(stderr, "%s\n", msg);
    snprintf(out, sizeof out, "%s", msg);
    syslog(LOG_INFO, "%s", msg);
    printf("ready\n");
}

/* ---- IV-05 대응: 상수 명령, 또는 인자를 분리해 exec ------------------------- */

void ping_host(void)
{
    system("ping -c 1 127.0.0.1");
    FILE *p = popen("uptime", "r");
    if (p) pclose(p);
    execl("/bin/ping", "ping", "-c", "1", "127.0.0.1", (char *)NULL);
}

/* ---- CE-03 대응: 사용 후 해제, 해제 후 NULL 또는 재할당 --------------------- */

void free_after_use(struct node *n)
{
    n->value = 1;
    free(n);
    n = NULL;
}

void free_then_reuse(char *p)
{
    free(p);
    p = malloc(32);
    if (p == NULL) return;
    p[0] = 'a';
    free(p);
}

void free_list(struct node *head)
{
    while (head) {
        struct node *next = head->next;
        free(head);
        head = next;                              /* 재할당 — 이후 사용은 새 값 */
    }
}

/* ---- TS-01 대응: 검사 없이 열고 결과로 판단, 또는 연 뒤 fstat ---------------- */

int write_if_allowed(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}

int read_size(const char *path)
{
    struct stat st;
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    if (fstat(fileno(f), &st) != 0) { fclose(f); return -1; }
    fclose(f);
    return (int)st.st_size;
}

/* ---- CE-02 대응: 모든 경로에서 fclose, 또는 핸들을 돌려주거나 보관 ---------- */

int first_byte(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int c = fgetc(f);
    fclose(f);
    return c;
}

FILE *open_log(const char *path)
{
    FILE *f = fopen(path, "a");
    return f;
}

void attach_log(struct app *app, const char *path)
{
    FILE *f = fopen(path, "a");
    app->log = f;                                 /* 소유권이 구조체로 이전 */
}

/* ---- CE-01 대응: NULL 검사 — if / assert / 헬퍼 함수 ----------------------- */

static void die_if_null(const void *p)
{
    if (p == NULL) { perror("alloc"); exit(1); }
}

struct node *make_node(void)
{
    struct node *n = malloc(sizeof *n);
    if (n == NULL) return NULL;
    n->value = 0;
    return n;
}

struct node *make_node_negated(void)
{
    struct node *n = malloc(sizeof *n);
    if (!n) return NULL;
    n->value = 0;
    return n;
}

struct node *make_node_assert(void)
{
    struct node *n = malloc(sizeof *n);
    assert(n != NULL);                            /* 오탐 실측: assert 검사 */
    n->value = 0;
    return n;
}

struct node *make_node_helper(void)
{
    struct node *n = malloc(sizeof *n);
    die_if_null(n);                               /* 오탐 실측: 헬퍼 함수 검사 */
    n->value = 0;
    return n;
}

int read_header(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    if (fgets(buf, (int)n, f) == NULL) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* ---- SF-03 대응: 최소 권한 ------------------------------------------------- */

void create_config(const char *path)
{
    chmod(path, 0600);
    int fd = open(path, O_CREAT | O_WRONLY, 0640);
    if (fd >= 0) close(fd);
    mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP);
    umask(077);
}

/* ---- SF-08 대응: OS 난수원, 또는 보안 무관 용도의 rand ----------------------- */

int make_session(unsigned char *token, size_t n)
{
    if (RAND_bytes(token, (int)n) != 1) return -1;
    unsigned char nonce[16];
    if (getrandom(nonce, sizeof nonce, 0) != (ssize_t)sizeof nonce) return -1;
    int dice = rand() % 6 + 1;                    /* 보안 용도 아님 — 이름 기준으로 제외 */
    return dice;
}

/* ---- SF-04 대응: SHA-256 / AES-GCM ----------------------------------------- */

const EVP_MD *digest(void)
{
    return EVP_sha256();
}

const EVP_CIPHER *cipher(void)
{
    return EVP_aes_256_gcm();
}

/* ---- AA-02 대응: 파일을 원자적으로 만드는 API ------------------------------- */

int make_temp(void)
{
    char tmpl[] = "/tmp/appXXXXXX";
    char cwd[4096];

    int fd = mkstemp(tmpl);
    if (fd >= 0) close(fd);
    if (getcwd(cwd, sizeof cwd) == NULL) return -1;
    return fd;
}
