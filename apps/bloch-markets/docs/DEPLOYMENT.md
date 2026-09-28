# Cloudflare Pages deployment

The existing direct-upload project is `blochmarkets`. Its production branch is
`main`; both `blochmarkets.xyz` and `blochmarkets.pages.dev` serve that deployment.
The project has no Pages Functions or Git provider integration. Deploy only
`apps/bloch-markets/public/`, never the repository root or local evidence files.

## Publish a reviewed revision

From `apps/bloch-markets`, run the validation suite and inspect the retained
examples:

```sh
npm test
node scripts/inspect.mjs public/studio/examples/lifecycle.json public/studio/examples/native-pair.json public/lab/example.json
```

Commit the intended release and ensure `git status --short` is empty. With an
authorized Cloudflare session, use the pinned Wrangler version:

```sh
npx wrangler@4.131.0 pages deploy public --project-name blochmarkets --branch markets-preview
```

Inspect the returned preview URL: home, Studio, Lab, example imports, review
exports and report rejection. Then publish the same committed files:

```sh
npx wrangler@4.131.0 pages deploy public --project-name blochmarkets --branch main
```

The explicit `main` flag selects the Cloudflare production environment; it does
not merge the local development branch into GitHub main. Credentials belong in
the local Wrangler login or a deployment environment, never this repository.
No deployment secret is required for the GitHub validation workflow.

## Verify and retain the rollback target

Record the previous production deployment ID before publishing. Confirm that
the new deployment has reached `deploy/success`, is the project's canonical
deployment, has the expected complete asset manifest and uses no Functions.
Check the production domain as well as the deployment URL. Compare served bytes
with local files, including all three example artifacts and their source pins;
check the security headers from `public/_headers` and module content types.

Cloudflare can inject its analytics beacon into HTML responses. The recovered
HTML contained that injection; removing exactly that script reproduced all
three original HTML asset hashes in the Cloudflare deployment manifest. The
source now omits the injected script and leaves the existing Cloudflare
analytics configuration in charge. Normalize only that known injection when
comparing HTTP HTML responses to source bytes.

The pre-release production deployment was
`24d9825d-0f4e-49e1-923e-2148107c672f`, available at
<https://24d9825d.blochmarkets.pages.dev>. It contains exactly the 26 recovered
asset paths. To roll back, select a retained successful production deployment
in the Cloudflare Pages dashboard and use **Rollback to this deployment**.
Recheck the custom domain after rollback.

Reference: [Cloudflare Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/).
