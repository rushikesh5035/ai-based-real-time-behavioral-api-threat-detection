const behaviorStore = new Map();

behaviorStore.reset = function resetBehaviorStore() {
	behaviorStore.clear();
};

module.exports = behaviorStore;
