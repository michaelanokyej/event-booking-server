const express = require("express");
const bodyParser = require("body-parser");
const graphqlHttp = require("express-graphql");
const mongoose = require("mongoose");

const graphiQlSchema = require("./graphql/schema/index");
const graphiQlResolvers = require("./graphql/resolvers/index");
// import the isAuth variable to use as a middleware
const isAuth = require("./middlewares/is-auth");

const app = express();

app.use(bodyParser.json());

// We need to accept all req from all ip address
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// Incoming graphQl queires use "query" to fetch
// data and "mutation" to change data

// GraphQL is a typed language so we have to define the
// type of endpoints we are going to support

// In the type object we define real endpoints
// we support


// we use the isAuth to check every incoming request
// that is why we always let requests move on to the next
app.use(isAuth);

app.use(
  "/graphql",
  graphqlHttp({
    schema: graphiQlSchema,
    rootValue: graphiQlResolvers,
    graphiql: true,
    // the above gives you the ability to play
    // with your api using the graphql interface
  })
);

// The rootValue is the resolver; it is what we expose
// to the front-end.

mongoose
  .connect(
    `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0-i6qfa.mongodb.net/${process.env.MONGO_DB}?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(5000);
  })
  .catch((err) => {
    console.log(err);
  });
