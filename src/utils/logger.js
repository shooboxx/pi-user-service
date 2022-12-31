const { createLogger, format, transports } = require('winston');
const { combine, timestamp, label, printf, json } = format;

const productionLogger = () => {
    return createLogger({
        level: 'debug',

        format: combine(
            timestamp(),
            json()
          ),
    
        defaultMeta: { service: 'user-service' },
        transports: [
            new transports.Console(),
            new transports.File({
                filename: 'errors.log',
                
              })
        ],
      });
}

const standardLogger = () => {
    const myFormat = printf(({ level, message, timestamp }) => {
        return `${timestamp} ${level}: ${message}`;
      });
    
    return createLogger({
        level: 'debug',
        // format: winston.format.simple(),
        format: combine(
            format.colorize(),
            label({ label: 'right meow!' }),
            timestamp({format: "HH:mm:ss"}),
            myFormat
          ),
    
        //defaultMeta: { service: 'user-service' },
        transports: [
            new transports.Console(),
            new transports.File({
                filename: 'errors.log',
                
              })
        ],
      });
}
  module.exports = {productionLogger, standardLogger};