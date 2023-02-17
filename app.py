import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get user's shares owned
    sharesOwned = db.execute("SELECT * FROM sharesOwned WHERE user_id = ?", session.get("user_id"))
    userInfo = db.execute("SELECT * FROM users WHERE id = ?", session.get("user_id"))

    # Get user's cash balance
    cashBalance = userInfo[0]["cash"]

    # Calculate total balance
    rows = len(db.execute("SELECT * FROM sharesOwned WHERE user_id = ?", session.get("user_id")))
    temp = 0
    totalBalance = 0

    while temp < rows:

        totalShares = db.execute("SELECT totalCost FROM sharesOwned WHERE user_id = ?", session.get("user_id"))[temp]["totalCost"]
        totalBalance += totalShares
        temp += 1

    totalBalance += cashBalance

    return render_template("index.html", sharesOwned=sharesOwned, usd=usd, lookup=lookup, cashBalance=cashBalance, totalBalance=totalBalance)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        check = lookup(symbol)

        # Ensures user input a symbol
        if not check or not symbol:

            return apology("Symbol does not exists")

        # Ensures sure user enters a valid amount of shares
        share = request.form.get("shares")

        try:
            # Handles fractional and decimals
            for char in share:

                if char == '.' or char == '/':

                    return apology("Please enter a valid amount of shares to be purchased")

            # Handles negative
            if not share or float(share) <= 0:

                return apology("Please enter a valid amount of shares to be purchased")

        except ValueError:

            return apology("Please enter a valid amount of shares to be purchased")

        # Stock's current price and the total amount user has to pay
        currentPrice = float("{:.2f}".format(check["price"]))
        totalAmount = currentPrice * float(share)

        balance = float("{:.2f}".format(db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))[0]["cash"]))

        # Checks if user has sufficient balance to purchase shares
        if balance > totalAmount:

            # Deduct from users balance
            balance -= totalAmount
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session.get("user_id"))

            description = f"Purchased {share} shares from {check['symbol']}"

            # Record transaction in database
            db.execute("INSERT INTO transactions (short_description, date_and_time, amount, user_id) VALUES (? , datetime('now','localtime'), -?, ?)",
                       description, totalAmount, session.get("user_id"))

            # Checks if company name exists
            if db.execute("SELECT * FROM sharesOwned WHERE symbol = ?", check['symbol']):

                # Update shares owned
                shares = db.execute("SELECT amount FROM sharesOwned WHERE symbol = ?", check['symbol'])[0]['amount']
                shares += int(share)

                # Update total cost
                totalCost = float("{:.2f}".format(db.execute(
                    "SELECT totalCost FROM sharesOwned WHERE symbol = ?", check['symbol'])[0]['totalCost']))
                totalCost += totalAmount

                db.execute("UPDATE sharesOwned SET amount = ?, totalCost = ? WHERE symbol = ?", shares, totalCost, check['symbol'])

            else:

                # If company name does not exists, create a new entry
                db.execute("INSERT INTO sharesOwned (amount, symbol, companyName, totalCost, user_id) VALUES (?, ?, ?, ?, ?)",
                           share, check['symbol'], check['name'], totalAmount, session.get("user_id"))

            # Redirect user to home page
            return redirect("/")

        else:

            # Return apology if balance is insufficient
            return apology("Insufficient amount of balance, purchase fail")

    else:

        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get all transactions made by user
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session.get("user_id"))

    return render_template("history.html", transactions=transactions, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for user
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":

        # Redirect user to form if requested via GET
        return render_template("quote.html")

    elif request.method == "POST":

        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing Symbol", 400)

        stock = lookup(symbol)

        if not stock:
            return apology("Stock not found", 400)

        return render_template("quoted.html", stock=stock, usd=usd)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":

        # When requested via GET, show registration form
        return render_template("register.html")

    elif request.method == "POST":

        # When form is submitted via POST, checks for possible errors and insert new users to database
        name = request.form.get("username")
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)

        if not name:

            return apology("must provide username", 400)

        elif len(rows) == 1:

            return apology("username exists", 400)

        password = request.form.get("password")
        if not password:
            return apology("must provide password", 400)

        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("must re-confirm password", 400)

        if password != confirmation:
            return apology("password does not match", 400)

        hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, hash)

        session["user_id"] = db.execute("SELECT id FROM users WHERE username = ?", name)[0]["id"]
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Get info of shares owned
    sharesOwned = db.execute("SELECT * FROM sharesOwned WHERE user_id = ?", session.get("user_id"))

    # User submitted a POST request when Sell button is clicked
    if request.method == "POST":

        symbol = request.form.get("symbol")
        amount = request.form.get("shares")

        # Checks if user has entered a symbol
        if not symbol:

            return apology("Invalid Symbol", 400)

        # Checks if user has entered a vali amount
        elif not amount or int(amount) <= 0:

            return apology("Invalid Amount", 400)

        # Checks if user has enough shares to sell
        elif int(amount) > int(sharesOwned[0]['amount']):

            return apology("Insufficient amount of shares", 400)

        # If all checks are passed, proceed to sell
        stockSelected = db.execute("SELECT * FROM sharesOwned WHERE symbol = ?", symbol)[0]

        # Update amount of shares owned
        currentAmount = stockSelected['amount']
        finalAmount = currentAmount - int(amount)

        # Update total cost of shares owned
        currentTotalCost = stockSelected['totalCost']
        price = lookup(symbol)['price']
        totalPrice = int(amount) * price
        finalTotalCost = currentTotalCost - totalPrice

        # Update shares owned
        db.execute("UPDATE sharesOwned SET amount = ?, totalCost = ? WHERE symbol = ?", finalAmount, finalTotalCost, symbol)

        # Update transaction history
        description = f"Sold {amount} shares from {symbol}"

        db.execute("INSERT INTO transactions (short_description, date_and_time, amount, user_id) VALUES (? , datetime('now','localtime'), +?, ?)",
                   description, totalPrice, session.get("user_id"))

        return redirect("/")

    return render_template("sell.html", sharesOwned=sharesOwned)


@app.route("/topup", methods=["GET", "POST"])
@login_required
def topup():

    # If user submitted a POST request, proceed to top up
    if request.method == "POST":

        amount = request.form.get("amount")
        username = request.form.get("username")
        password = request.form.get("password")

        # Checks if user has entered a valid amount
        if not amount or float(amount) <= 0:

            return apology("Invalid Amount", 400)

        # Query database for user
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Checks if user has entered a valid username
        if not username or len(rows) != 1:

            return apology("Invalid Username", 400)

        # Checks if user has entered a valid password
        if not password or not check_password_hash(rows[0]["hash"], password):

            return apology("Invalid Password", 400)

        db.execute("UPDATE users SET cash = cash + ? WHERE username = ?", amount, username)

        return redirect("/")

    return render_template("topup.html")

