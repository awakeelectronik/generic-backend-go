package application

// MaxPageSize caps how many rows a single paginated response may return,
// bounding the work any one request can ask the DB to do. Shared by the list
// use cases and handlers so the limit lives in one place.
const MaxPageSize = 100
