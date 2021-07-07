/**
  resolves to an ARRAY with all users, each user having { user_id, username }
 */
const db = require('../../data/db-config')
function find() {
  return db('users')
    .select('user_id', 'username')
}

/**
  resolves to an ARRAY with all users that match the filter condition
 */
function findBy(filter) {
  return db('users')
    .where(filter)

}

/**
  resolves to the user { user_id, username } with the given user_id
 */
function findById(user_id) {
  return db('users')
    .select('user_id', 'username')
    .where({ user_id })
    .then(data => {
      return data[0]
    })
}

/**
  resolves to the newly inserted user { user_id, username }
 */
function add(user) {
  return db('users')
    .insert(user)
    .then(ids => {
      return findById(ids[0])
    })
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = { find, findBy, findById, add }