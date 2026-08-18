# Audit Companion

Build a security audit management app called AuditKit. It has a Supabase backend with four tables: clients, audits, checklist_items, and audit_findings. The main flow is: create a client, start an audit for that client, work through a checklist of security items organized into 7 categories, mark each item as Pass/Fail/NA with notes, then generate a report. The audit view should have a left sidebar with category tabs showing completion percentage, and a right panel showing checklist items with Pass/Fail/NA buttons and an expandable notes field on Fail. Include a dashboard showing active audits and a client list page. Use Supabase auth for login. Seed the checklist_items table with the 35 items I’ll provide after the initial build. Design should be clean and professional — dark navy header, white content areas, severity badges in red/orange/yellow/green.”

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://audit-buddy-53.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/a5b4dd7a-0dc8-47a8-9c38-beb7da432fd9).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
