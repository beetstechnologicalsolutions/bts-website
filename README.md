# BTS website

The website for BTS (Beets Technological Solutions). It is a single HTML page with no WordPress, database or server code, hosted free on Vercel from this GitHub repository.

## What's in here

| Path | What it is |
|---|---|
| `public/index.html` | The whole website |
| `public/favicon.svg` | The BTS logo mark (pink B-T-S monogram on navy), used as the browser tab icon |
| `public/apple-touch-icon.png` | The same mark as a 180 px icon for iPhone and iPad home screens |
| `tests/` | The security checks that run before every deploy |
| `tests/fingerprint.json` | The approved fingerprint of the design (everything except the news and vulnerability data) |
| `vercel.json` | Vercel settings: runs the checks, publishes `public/`, and adds security headers |
| `.github/workflows/checks.yml` | Runs the same checks on GitHub whenever anything is pushed |
| `.github/workflows/kev-alert.yml` | Every 10 minutes, checks CISA's Known Exploited Vulnerabilities list and opens an issue (which GitHub emails you about) when a new entry isn't on the site yet |
| `.github/scripts/kev-alert.mjs` | The script the KEV alert runs. It only reads CISA's public data and never changes the site |
| `.github/workflows/site-watch.yml` | Every 5 minutes, downloads the live site and runs the tamper, security and injection checks plus a security-header check. Opens a "SECURITY ALERT" issue if anything fails |
| `.github/workflows/change-watch.yml` | Runs on every push. Opens a "CHANGE ALERT" issue if anything other than the news and vulnerability data changed, or if history was rewritten |
| `.github/scripts/change-watch.mjs`, `.github/scripts/header-check.mjs` | The scripts those two watches run |

## How updates are protected

Vercel runs `npm test` before every deploy. It checks three things:

1. **Tamper fingerprint.** The design, wording, contact details and code must match `tests/fingerprint.json`. Only the news and vulnerability data may change.
2. **Security check.** No outside scripts, frames or forms that send data away, every vulnerability has a real CVE number, and every link is https from a safe kind of site.
3. **Injection test.** Loads the page with deliberately malicious data and makes sure none of it runs.

If any check fails, the deploy fails and Vercel keeps the last good version live. To roll back by hand, open the project in Vercel, go to Deployments, pick an earlier one and choose "Promote to Production".

Vercel also sends security headers with every page. They block outside scripts, stop other sites framing the page, force https, and switch off camera, microphone and location access.

## Set it up (one time)

1. **GitHub.** Create a free account at github.com if you don't have one. Create a new repository called `bts-website` (private is fine) and upload everything in this folder, keeping the folder structure.
2. **Vercel.** Sign up free at vercel.com with "Continue with GitHub". Choose "Add New, Project", import `bts-website`, leave the settings as they are and press Deploy. Your site will be live at an address like `bts-website.vercel.app`.
3. **Your own domain (optional).** In the Vercel project, go to Settings, Domains and add your domain (for example `beetstech.co.uk`). Vercel shows the DNS records to add at your domain registrar.
4. **Secure both accounts.** Turn on two-factor authentication for GitHub and Vercel, preferably with an authenticator app or passkey. Anyone who controls these accounts controls the site.

## Making changes

- **News and vulnerabilities:** the scheduled update task edits only the data block between `/* DATA:START */` and `/* DATA:END */` in `public/index.html` and commits it. Vercel then tests and deploys it automatically.
- **Design or wording changes:** after an approved change, make a new fingerprint with `npm run fingerprint` and commit it with the change. Without a new fingerprint, the deploy will fail on purpose.
