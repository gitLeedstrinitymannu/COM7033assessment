from flask import Flask, render_template

# Initialize Flask application
app = Flask(__name__)

# Home route
@app.route('/')
def home():
    return render_template('index.html')

#Test API route
@app.route('/api')
def api():
    return {
        "message" : "Flask app connected successfully!",
        "status" : "sucess"
    }

# Run application
if __name__ == '__main__':
    app.run(debug=True)