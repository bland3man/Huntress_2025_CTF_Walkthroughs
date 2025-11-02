# in WSL or Linux
npm init -y
npm i -D playwright
# run once to download browsers (Playwright will prompt) — or:
npx playwright install --with-deps


export BASE_URL='https://06efeb0c.proxy.coursestack.com'
export TOKEN_FRAG='token=06efeb0c-c4f6-4b90-bf59-1cad111b9626_1_f...&user=admin'  # include full fragment if you captured more params
export CODES='000000,111111,123456,424242,013cb9' # include the code(s) you want to try
node ofa-verify.js

Set headless: false in the script if you want to watch the browser.