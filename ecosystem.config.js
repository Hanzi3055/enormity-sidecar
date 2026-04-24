module.exports = {
  apps: [
    {
      name: 'enormity-sidecar',
      script: '/opt/enormity-sidecar/server.js',
      cwd: '/opt/enormity-sidecar',
      instances: 1,
      autorestart: true,
      watch: false,
      node_args: '--max-old-space-size=512',
      max_memory_restart: '512M',
      restart_delay: 3000,
      max_restarts: 10,
      min_uptime: '10s',
      env: {
        NODE_ENV: 'production',
        PORT: 3100
      },
      error_file: '/opt/enormity-sidecar/logs/err.log',
      out_file: '/opt/enormity-sidecar/logs/out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      merge_logs: true
    },
    {
      name: 'enormity-healer',
      script: '/usr/local/bin/auto-heal-server.js',
      cwd: '/usr/local/bin',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '256M',
      restart_delay: 5000,
      max_restarts: 5,
      error_file: '/opt/enormity-sidecar/logs/healer-err.log',
      out_file: '/opt/enormity-sidecar/logs/healer-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss'
    }
  ]
};
