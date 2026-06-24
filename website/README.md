# tenant-tail documentation website

This directory contains the Docusaurus v3 documentation site for `tenant-tail`.

## Local Development

```bash
npm install
npm run start
```

This starts a local development server and opens a browser window. Most changes are reflected live without restarting.

## Build

```bash
npm run build
```

This generates static content into the `build` directory. The build enforces `onBrokenLinks: 'throw'`, so any broken internal link will fail the build.

## Serve

```bash
npm run serve
```

Serves the production build locally for testing.

## Deployment

This site is deployed to GitHub Pages via the `.github/workflows/deploy-docs.yml` workflow. It triggers on pushes to `main` that modify `website/**` or the workflow file itself.

To enable deployment, go to **Settings > Pages** in the GitHub repository and set the source to **GitHub Actions**.
