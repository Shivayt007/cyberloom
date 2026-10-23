# Cyberloom Link Inspector

Mobile-friendly website that opens a Cyberloom short link with Playwright, shows redirect stages and live terminal logs, verifies a MessyCloud destination, and extracts candidate download links.

## EasyPanel

1. Create a new App service and select GitHub repo `Shivayt007/cyberloom` branch `main`.
2. Use Dockerfile build (`Dockerfile` in repo root).
3. Set environment variable `APP_PASSWORD` to a strong random value. Optional: `ALLOWED_START_HOSTS=cyberloom.best,www.cyberloom.best` and `TARGET_HOSTS=messycloud.ink,www.messycloud.ink`.
4. Expose HTTP on container port `8000`, add a domain, and deploy.
5. Visit the website; paste a URL and enter the password from EasyPanel. Health endpoint is `/health`.

The tool does not bypass CAPTCHA or server-side access checks and cannot guarantee that changing shortener sites will allow scraping. Keep the service private and restrict server networking: it runs a real browser on external sites. The official Playwright browser Docker image can be large.

If the app is connected to a repository, click Deploy in EasyPanel after the code push; auto-deployment requires EasyPanel configuration.
