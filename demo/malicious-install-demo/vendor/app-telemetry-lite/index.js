// Innocuous on the surface - this is what makes the postinstall script the
// real danger: nobody reviews index.js expecting the attack to be here.
module.exports = {
  track(event) {
    // no-op - this package never actually does anything useful.
    // eslint-disable-next-line no-unused-vars
    void event;
  },
};
