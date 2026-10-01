# Proxy Suite (web)

Flask front end for `proxy_suite.py`: collect free public proxies from 67 sources, test them, filter and export.

Sources live in `proxy_suite.py` (`SOURCES`, `SOURCE_PROTOCOL`). Add a line there to add a source; the in-page source report shows which ones are dead.

## Run locally
    pip install -r requirements.txt
    python app.py          # http://localhost:5000

## Deploy on Render
1. Push this folder to a GitHub repo.
2. Render dashboard -> New -> Blueprint -> pick the repo (it reads `render.yaml`).
3. Wait for the build, then open the `.onrender.com` URL.

Free-plan notes: the service sleeps after ~15 min idle (first visit takes ~30 s to wake),
and running jobs are lost on restart. Tune limits with the env vars in `render.yaml`.
