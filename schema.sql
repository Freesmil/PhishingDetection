CREATE TABLE blacklist (
    "id" serial NOT NULL,
    "domain" text NOT NULL UNIQUE,
    PRIMARY KEY ("id")
);
