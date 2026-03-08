module;

#include "galay-mongo/module/ModulePrelude.hpp"
#include "galay-mongo/base/MongoConfig.h"
#include "galay-mongo/base/MongoError.h"
#include "galay-mongo/base/MongoLog.h"
#include "galay-mongo/base/MongoValue.h"
#include "galay-mongo/protocol/Builder.h"
#include "galay-mongo/async/AsyncMongoConfig.h"
#include "galay-mongo/async/AsyncMongoClient.h"
#include "galay-mongo/sync/MongoClient.h"

export module galay.mongo;

export using ::galay::mongo::MongoConfig;
export using ::galay::mongo::MongoErrorType;
export using ::galay::mongo::MongoError;
export using ::galay::mongo::MongoLogger;
export using ::galay::mongo::MongoValueType;
export using ::galay::mongo::MongoValue;
export using ::galay::mongo::MongoDocument;
export using ::galay::mongo::MongoArray;
export using ::galay::mongo::MongoReply;
export using ::galay::mongo::protocol::MongoCommandBuilder;
export using ::galay::mongo::AsyncMongoConfig;
export using ::galay::mongo::MongoConnectAwaitable;
export using ::galay::mongo::MongoCommandAwaitable;
export using ::galay::mongo::MongoPipelineResponse;
export using ::galay::mongo::MongoPipelineAwaitable;
export using ::galay::mongo::AsyncMongoClient;
export using ::galay::mongo::MongoClient;
export using ::galay::mongo::MongoResult;
export using ::galay::mongo::MongoVoidResult;
