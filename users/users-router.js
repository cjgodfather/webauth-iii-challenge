const router = require("express").Router();

const Users = require("./users-model.js");
const restricted = require("../auth/restricted-middleware.js");

router.get("/", restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// function checkRole(roles) {
//   return function(req, res, next) {
//     if (roles.includes(req.decodedJwt.role)) {
//       next();
//     } else {
//       res.status(403).message({ message: "wrong role" });
//     }
//   };
// }
module.exports = router;
