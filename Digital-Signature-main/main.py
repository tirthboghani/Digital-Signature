from flask import Flask, render_template, request, redirect, url_for, flash
import rsa

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Global variables
public_key = None
private_key = None
message = None
signature = None


# Define the restart route at the top level, outside of any other route function
@app.route("/restart", methods=["GET"])
def restart_process():
    global public_key, private_key, message, signature
    # Reset all global variables
    public_key = None
    private_key = None
    message = None
    signature = None
    flash("Process restarted. You can start fresh!", "success")
    return redirect(url_for("home"))


@app.route("/", methods=["GET", "POST"])
def home():
    global public_key, private_key, message
    if request.method == "POST":
        # Get message from form
        message = request.form.get("message")
        if not message:
            flash("Message cannot be empty!", "error")
            return render_template("home.html")

        # Generate keys
        public_key, private_key = rsa.newkeys(2048)
        flash("Keys generated successfully!", "success")
        return render_template(
            "home.html",
            message=message,
            public_key=str(public_key),
            private_key=str(private_key),
        )

    return render_template("home.html")


@app.route("/sign", methods=["GET", "POST"])
def sign_message():
    global public_key, private_key, message, signature
    if not public_key or not private_key:
        flash("You need to generate keys first!", "error")
        return redirect(url_for("home"))

    if request.method == "POST":
        if not message:
            flash("No message available to sign!", "error")
            return redirect(url_for("home"))

        # Sign the message
        try:
            signature = rsa.sign(message.encode("utf-8"), private_key, "SHA-256")
            flash("Message signed successfully!", "success")
            return render_template(
                "sign_message.html", message=message, signature=signature.hex()
            )
        except Exception as e:
            flash(f"An error occurred: {e}", "error")
            return render_template("sign_message.html", message=message)

    return render_template("sign_message.html", message=message)


@app.route("/verify", methods=["GET", "POST"])
def verify_signature():
    global public_key, message
    if request.method == "POST":
        input_message = request.form.get("message")
        input_signature = request.form.get("signature")

        if not input_message or not input_signature:
            flash("Message and signature cannot be empty!", "error")
            return render_template("verify.html")

        try:
            rsa.verify(
                input_message.encode("utf-8"),
                bytes.fromhex(input_signature),
                public_key,
            )
            flash("The signature is VALID. The message is authentic.", "success")
            return render_template(
                "verify.html", valid=True, original_message=input_message
            )
        except rsa.VerificationError:
            flash(
                "The signature is INVALID. The message may have been tampered with.",
                "error",
            )
            return render_template("verify.html")
        except Exception as e:
            flash(f"An error occurred: {e}", "error")
            return render_template("verify.html")

    return render_template("verify.html")


if __name__ == "__main__":
    app.run(debug=True)
