CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username TEXT NOT NULL, hash TEXT NOT NULL,
    cash NUMERIC NOT NULL DEFAULT 10000.00
)

CREATE TABLE transactions(
    transaction_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    short_description TEXT NOT NULL,
    date_and_time TEXT NOT NULL,
    amount REAL NOT NULL,
    user_id INTEGER NOT NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
)

CREATE TABLE sharesOwned(
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    amount INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    companyName TEXT NOT NULL,
    totalCost REAL NOT NULL,
    user_id INTEGER NOT NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
)

-- Resets transactions AUTO_INCREMENT
DELETE FROM sqlite_sequence WHERE name = 'transactions';

