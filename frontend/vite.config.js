import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// CORS 대응: dev 서버가 /api를 Django(127.0.0.1:8000)로 프록시한다.
// 브라우저 입장에선 same-origin이라 CORS가 발생하지 않는다 —
// django-cors-headers 의존성도, 백엔드 settings 수정도 불필요 (docs/decisions.md).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
});
