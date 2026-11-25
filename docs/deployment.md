# Deployment guide

The Flask development server (`python app.py`) is for local use only.

## Production checklist
1. **Secrets.** Set `SECRET_KEY`, `FIELD_ENCRYPTION_KEY`, `MONGO_URI` as real environment variables on the
   server (not in the repository). Set `FLASK_ENV=production` so the session cookie is HTTPS-only.
   Back up `FIELD_ENCRYPTION_KEY` separately from the database backups.
2. **HTTPS.** Run behind a reverse proxy (nginx, Caddy or a cloud load balancer) with a TLS certificate.
3. **WSGI server.** Use gunicorn (not the development server):
   ```
   pip install gunicorn
   gunicorn "app:create_app()" --bind 127.0.0.1:8000 --workers 2
   ```
4. **MongoDB Atlas.** Restrict Network Access to the server's IP (not `0.0.0.0/0`), give the app user only
   the database it needs, and enable Atlas backups.
5. **SQLite.** Keep `instance/app.db` outside the web root, owned by the app user, with regular backups.
6. **Accounts.** Create the first admin with `python create_user.py --role admin` on the server.
7. **Monitoring.** Watch the console for `AUDIT LOG ERROR`; review the audit log regularly.

## Optional: Docker
A minimal image would copy the project, run `pip install -r requirements.txt` and start gunicorn as above,
with secrets passed as environment variables at run time (never baked into the image).
