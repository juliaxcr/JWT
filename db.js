const Sequelize = require('sequelize');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const secret = process.env.JWT
const { STRING } = Sequelize;
const config = {
  logging: false
};

if(process.env.LOGGING){
  delete config.logging;
}
const conn = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost/acme_db', config);

const Note = conn.define('note', {
  text: STRING,
})

const User = conn.define('user', {
  username: STRING,
  password: STRING
});

User.beforeCreate(async (user) => {
  const SALT_COUNT = 5;
  const hashPassword = await bcrypt.hash(user.password, SALT_COUNT);
  user.password = hashPassword;
})

User.byToken = async(token)=> {
  try {
    const data = await jwt.verify(token, secret);
    if(data){
      const user = await User.findByPk(data.userId); //only find with user id
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
  catch(ex){
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

User.authenticate = async({ username, password })=> {
  const user = await User.findOne({
    where: {
      username
    }
  });
  const isValid = await bcrypt.compare(password, user.password)
  if (user && isValid){
    const data = await jwt.sign({userId: user.id}, secret)
    return data; //return token - generate token
  }
  const error = Error('bad credentials');
  error.status = 401;
  throw error;
};

const syncAndSeed = async()=> {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw'},
    { username: 'moe', password: 'moe_pw'},
    { username: 'larry', password: 'larry_pw'}
  ];

  const notes = [
    { text: "lucy's note" },
    { text: "moe's note" },
    { text: "larry's note" },
  ]

  const [lucy, moe, larry] = await Promise.all(
    credentials.map( credential => User.create(credential))
  );

  const [luNote, mNote, laNote] = await Promise.all(
    notes.map( note => Note.create(note))
  );
  
  // creating associations
  lucy.addNote(luNote);
  moe.addNote(mNote);
  larry.addNote(laNote);

  return {
    users: {
      lucy,
      moe,
      larry
    },
    notes: {
      luNote,
      mNote,
      laNote
    }
  };
};

// defining associations
User.hasMany(Note);
Note.belongsTo(User);

module.exports = {
  syncAndSeed,
  models: {
    User,
    Note
  }
};
