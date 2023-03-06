const jwt = require('jsonwebtoken');

const isAuth = async (accessToken) => {
  if (!accessToken) {
    return false;
  }
  if (accessToken === undefined) {
    return false;
  }
  const token = accessToken.split(' ')[1];
  if (!token || token === '') {
    return false;
  }
  
  let decodedToken;
  try {
    decodedToken = jwt.verify(token, 'somesupersecretkey');
    
  } catch (err) {
    return false;
  }
  if (!decodedToken) {
    return false;
  }
  
  return  true;
};
module.exports = isAuth;