import demoScenarioJson from './fixtures/tls-migration-demo.json';
import type { BreakLabScenario, WorkspaceFile } from './types';

// Same scenario shipped in scenarios/tls-migration-demo.json — copied in so
// the dashboard has a real, deterministic scenario to run BreakLab against
// without needing a file-upload step of its own. It intentionally fails its
// policy (see releaseExpectation) so a first run has something to show.
export const DEMO_SCENARIO = demoScenarioJson as unknown as BreakLabScenario;

export const EXAMPLE_WORKSPACES: Record<string, WorkspaceFile[]> = {
  'Nginx (classical groups)': [
    { path: 'nginx.conf', content: 'server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2 TLSv1.3;\n  ssl_ecdh_curve X25519:prime256v1;\n}\n' }
  ],
  'HAProxy (classical curves, legacy TLS)': [
    {
      path: 'haproxy.cfg', content:
        'global\n  ssl-default-bind-curves X25519:P-256\n  ssl-default-server-curves X25519:secp384r1\n  ssl-default-bind-options ssl-min-ver TLSv1.1 no-tls-tickets\n\n'
        + 'frontend https\n  bind *:443 ssl crt /etc/haproxy/cert.pem\n  default_backend application\n\nbackend application\n  server app 127.0.0.1:8080\n'
    }
  ],
  'Apache mod_ssl (classical group)': [
    {
      path: 'apache-ssl.conf', content:
        '<VirtualHost *:443>\n  SSLEngine on\n  SSLOpenSSLConfCmd Curves X25519:prime256v1:secp384r1\n'
        + '  SSLCertificateFile /etc/apache2/cert.pem\n  SSLCertificateKeyFile /etc/apache2/key.pem\n</VirtualHost>\n'
    }
  ]
};
