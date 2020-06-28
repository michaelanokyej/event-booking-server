const { buildSchema } = require("graphql");

module.exports = buildSchema(`
    type Booking {
      _id: ID
      event: Event!
      user: User!
      createdAt: String!
      updatedAt: String!
    }
    type Event {
      _id: ID!
      title: String!
      category: String!
      description: String!
      price: Float!
      date: String!
      creator: User!
    }

    type User {
      _id: ID!
      email: String!
      password: String
      username: String!
      createdEvents: [Event!]
    }

    type AuthData {
      userId: ID!
      token: String!
      tokenExpiration: Int!
      username: String!
    }

    input UserInput {
      first_name: String!
      last_name: String!
      username: String!
      email: String!
      password: String!
    }

    input EventInput {
      title: String!
      category: String!
      description: String!
      price: Float!
      date: String!
    }

    type RootQuery {
      events: [Event!]!
      bookings: [Booking!]!
      login(email: String!, password: String!): AuthData!
    }

    type RootMutation {
      createEvent(eventInput: EventInput): Event
      createUser(userInput: UserInput): AuthData!
      bookEvent(eventId: ID!): Booking!
      cancelBooking(bookingId: ID!): Event!
    }

    schema {
      query: RootQuery,
      mutation: RootMutation
    }
  `);
