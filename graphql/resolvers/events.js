const Event = require("../../models/event");
const User = require("../../models/user");
const { transformEvent } = require("../resolvers/mergeHelpers")

module.exports = {
  events: async () => {
    try {
      const events = await Event.find();
      return events.map((event) => {
        // with mongoose we can access the objectID as a String
        // by just giving our return object the "id" key like below with "event.id"
        return transformEvent(event)
      });
    } catch (err) {
      console.log(err)
      throw err;
    }
  },
  createEvent: async (args, req) => {
    // check if isAuth is true before 
    // user can create a user
    if(!req.isAuth) {
      throw new Error("Sign in/up to create event")
    }
    console.log(args.eventInput)

    // create event using event model
    const event = new Event({
      title: args.eventInput.title,
      category: args.eventInput.category,
      description: args.eventInput.description,
      price: +args.eventInput.price,
      date: new Date(args.eventInput.date),
      creator: req.userId,
    });
    let createdEvent;
    try {
      const result = await event.save();
      createdEvent = transformEvent(result)
      const creator = await User.findById(req.userId);
      if (!creator) {
        throw new Error("User does not exist");
      }
      creator.createdEvents.push(event);
      await creator.save();
      return createdEvent;
    } catch (err) {
      throw err;
    }
  }
};