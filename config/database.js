const mongoose = require('mongoose');

const dbConnection = () => {
  mongoose.set('strictQuery', false);

  mongoose
    .connect(process.env.DB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then((conn) => {
      console.log(`Database Connected: ${conn.connection.host}`);
    })
    .catch((err) => {
      console.error(`Database Error: ${err}`);
      process.exit(1); 
    });
};

module.exports = dbConnection;
