web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60
release: python -c "from app import init_db; init_db()"
