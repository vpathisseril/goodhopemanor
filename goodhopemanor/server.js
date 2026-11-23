'use strict';
const {initialize}=require('./src/app');
initialize().then(({server,config})=>{
  server.listen(config.port,()=>console.log(`Good Hope Manor server listening on port ${server.address().port}`));
}).catch(error=>{console.error('Startup aborted:',error.message);process.exitCode=1;});
