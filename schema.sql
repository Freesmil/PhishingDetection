CREATE TABLE blacklist (
    "id" serial NOT NULL,
    "domain" text NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE whitelist (
    "id" serial NOT NULL,
    "domain" text NOT NULL,
    PRIMARY KEY ("id")
);

