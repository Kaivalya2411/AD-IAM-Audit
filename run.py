"""
run.py — Entry point for AD/IAM Auditor
Usage:  python run.py
Needs:  pip install flask
"""
from app import create_app
from app.models.database import init_db, migrate_db

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        init_db()
        migrate_db()
    print("\n" + "═" * 50)
    print("  AD/IAM Auditor  |  http://localhost:5000")
    print("  Open your browser and go to that URL.")
    print("═" * 50 + "\n")
    app.run(debug=True, port=5000)
