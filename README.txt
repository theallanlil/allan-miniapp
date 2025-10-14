# Farcaster Mini App — Hello Warpcast

Quick start:
1) Replace YOUR_DOMAIN in files with your actual domain.
2) Deploy folder to Vercel (Upload → drop folder).
3) Visit /.well-known/farcaster.json to verify manifest.
4) Open Mini App Debug Tool in Farcaster → Preview https://YOUR_DOMAIN/

Notes:
- Uses CDN import of @farcaster/miniapp-sdk.
- Requires sdk.actions.ready() before SDK use.
