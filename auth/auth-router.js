const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("../users/users-model.js");

router.post("/register", (req, res) => {
  let user = req.body;
  //always validate data before sending it to the db
  // call validateUser to validate user
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  db.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post("/login", (req, res) => {
  let { username, password } = req.body;

  db.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        //produce a token here
        const token = getJwtToken(user.username);

        //send the token to client
        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token
        });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function getJwtToken(username) {
  const payload = {
    username
    // role: "student" this will probably come from the database
  };

  const secret = process.env.JWT_SECRET || "is it secret?";

  const options = {
    expiresIn: "1d"
  };
  return jwt.sign(payload, secret, options);
}

module.exports = router;
