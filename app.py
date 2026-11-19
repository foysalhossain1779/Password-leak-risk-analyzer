from flask import Flask, render_template, request
from password_analyzer import analyze_password, load_common_passwords

# Initialize the local Flask application and load offline password list
app = Flask(__name__)
COMMON_PASSWORDS = load_common_passwords()


# Serve the main page and run local security analysis on form submission
@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None

    # Evaluate the submitted password locally without network requests
    if request.method == "POST":
        password = request.form.get("password", "")
        if password:
            analysis_result = analyze_password(password, COMMON_PASSWORDS)

    return render_template("index.html", result=analysis_result)


# Run the server locally on your machine
if __name__ == "__main__":
    app.run(debug=True)