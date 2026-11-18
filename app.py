from flask import Flask, render_template

from database import check_mongo, check_sqlite, init_sqlite

# Initialize Flask application
app = Flask(__name__)

# Create SQLite tables on startup
init_sqlite()


# Home route
@app.route('/')
def home():
    return render_template('index.html')


# Test API route
@app.route('/api')
def api():
    return {
        "message": "Flask app connected successfully!",
        "status": "success"
    }


# Database connection test route
@app.route('/api/db-status')
def db_status():
    return {
        "sqlite": check_sqlite(),
        "mongodb": check_mongo()
    }


# Run application
if __name__ == '__main__':
    app.run(debug=True, port=5001)  # debug mode is for local development only