"""run.py — starts the server, nothing else."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)