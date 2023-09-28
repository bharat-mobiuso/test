const express = require("express")
const os = require("os")
const cluster = require("cluster")
const MongoClient = require('mongodb').MongoClient;
const fileUpload = require('express-fileupload');
const csv = require('csv-parser');
const fs = require('fs');
var htmlpath = require('path');
const bodyParser = require('body-parser');
const { google } = require('googleapis');
const readline = require('readline');
var cors = require('cors');
const https = require('https');
ActiveDirectory = require('activedirectory');
const compression = require('compression');
const CryptoJS = require("crypto-js");
const fetch = require('node-fetch');
var moment = require('moment-timezone');
const nodemailer = require('nodemailer');
const converter = require('json-2-csv');
const { parse } = require('json2csv');
const { v5: uuidv5 } = require('uuid');
const axios = require('axios').default;
const xlsxreader = require('xlsx');
const cookieParser = require('cookie-parser');
const {constants} = require("crypto");
const nocache = require("nocache");
const csrf = require('csurf');
const {doubleCsrf} = require("csrf-csrf");
const helmet = require('helmet')

// ## snippet to generate SHA hash for script file
// const crypto = require('crypto');
// const file = fs.readFileSync('./notificationBroadcast.js');
// const hash = crypto.createHash('sha256').update(file).digest('base64');
// console.log(`Hash: sha256-${hash}`);

// constants for configuration
const config = {
    ciphers: 'EECDH+AES128:EECDH+3DES:EDH+3DES:!SSLv2:!MD5:!DSS:!aNULL',
    AESSecretKey: 'bsl#123%$^#&#',
    AD_LOGIN_BASE_URL: 'http://chatbotdev.bluestarindia.com',
    SCOPES: ['https://www.googleapis.com/auth/spreadsheets'],
    TOKEN_PATH: './googlesheet/token.json',
    generateReportFilePath: "https://sv.bluestarindia.com/uploadedFiles/",
    uploadedFolderPath: ""
}

// This is the important stuff
// Prevent Old Cipher Suites / Old SSL/TLS Version
const optionshttps = {
    secureOptions: constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1,
    ciphers: config.ciphers,
    honorCipherOrder: true,
    key: fs.readFileSync('./cert/sv.bluestarindia.com.key'),
    cert: fs.readFileSync('./cert/star_bluestarindia_com.crt'),
    ca: fs.readFileSync('./cert/DigiCertCA.crt'),
    sessionTimeout: 9000000                  // equals to 30 min
};

const AESSecretKey = 'bsl#123%$^#&#'
const AD_LOGIN_BASE_URL = 'http://chatbotdev.bluestarindia.com'

const PORT = process.env.PORT || 443
const clusterWorkerSize = os.cpus().length
const whiteListedOrigin = ['13.233.50.179', '13.233.53.26', '13.232.31.17'];

//////////////
const SCOPES = ['https://www.googleapis.com/auth/spreadsheets'];
const TOKEN_PATH = './googlesheet/token.json';
let oAuth2Client;
let ccontent;
let ttoken;

fs.readFile('./googlesheet/credentials.json', (err, content) => {
    if (err) return console.log('Error loading client secret file:', err);
    // Authorize a client with credentials, then call the Google Sheets API.
    ccontent = content;
    authorize(JSON.parse(content));
});

function authorize(credentials) {
    const {client_secret, client_id, redirect_uris} = credentials.installed;
    oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);

    // Check if we have previously stored a token.
    fs.readFile(TOKEN_PATH, (err, token) => {
        if (err) return getNewToken(oAuth2Client);
        var ttoken = token;
        oAuth2Client.setCredentials(JSON.parse(token));
        //listMajors(oAuth2Client);
        console.log("value of auth is set");
    });
}

function getNewToken(oAuth2Client) {
    const authUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
    });
    console.log('Authorize this app by visiting this url:', authUrl);
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    rl.question('Enter the code from that page here: ', (code) => {
        rl.close();
        oAuth2Client.getToken(code, (err, token) => {
            if (err) return console.error('Error while trying to retrieve access token', err);
            oAuth2Client.setCredentials(token);
            // Store the token to disk for later program executions
            fs.writeFile(TOKEN_PATH, JSON.stringify(token), (err) => {
                if (err) return console.error(err);
                console.log('Token stored to', TOKEN_PATH);
            });
        });
    });
}

//////////////

if (cluster.isMaster) {
    for (let i = 0; i < clusterWorkerSize; i++) {
        cluster.fork()
    }

    cluster.on("exit", function (worker) {
        console.log("Worker", worker.id, " has exited.")
    })
} else {
    // ## ---------------------------------- APP CONFIGURATION BEGINS HERE ------------------------------------- ## //
    // Avoid Vulnerability like HTTP Host Header injection /HTTP OPTIONS method enabled etc.
    const customMiddleware = (req, res, next) => {
        if (req.hostname !== 'sv.bluestarindia.com') {
            res.status(400).send('Request Not Allowed as Host is invalid');
        } else if (req.method === 'OPTIONS') {
            res.status(405).send('Method Not Allowed');
        } else {
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
            res.setHeader('X-XSS-Protection', '1; mode=block');
            next();
        }
    }

    const app = express()
    const router = express.Router();

    // app config
    app.use(customMiddleware); // Middleware chain 1 of 2
    app.use(express.static(__dirname + '/public'));
    app.use(compression());
    app.use(cookieParser("yiE4JJdJFUwR1v5FPQZB")); // Required for csrf-csrf
    app.use(nocache());         // Prevent Browser Cache
    app.use(bodyParser.json());
    app.use(fileUpload());
    app.use(bodyParser.urlencoded({extended: true}));
    app.use(bodyParser.json({limit: '50mb', extended: true}));
    // Prevent Cross-Origin Resource Sharing (CORS) / HTTP OPTIONS Method
    // ******* Please make origin * to enable access to another origin
    // (not recommended for security purpose) *****
    app.use(cors({
        "origin": "*",
        "methods": 'GET, POST',
        "preflightContinue": false,
        "optionsSuccessStatus": 204,
        "exposedHeaders": "Content-Type, authToken, Authorization, CSRF-Token, Division, Same-Origin-Allow-Origin",
        "allowedHeaders": "Content-Type, authToken, Authorization, CSRF-Token, Division",
        "credentials": true
    }));
    app.use(csrf({cookie: false})); // Prevent insecure Cookies

    // CSRF-TOKEN configuration
    const {
        invalidCsrfTokenError,
        generateToken,
        doubleCsrfProtection
    } = doubleCsrf({
        getSecret: (req) => req.secret,
        secret: 'secret-v5FP-wR1v5FPQZB',
        cookieName: 'csrf-cookie-name-wR1v5FPQZB',
        cookieOptions: {path: '/login', sameSite: true, secure: true, signed: true},
        size: 64,
        ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    });

    // Error handling, validation error interception
    const csrfErrorHandler = (error, req, res, next) => {
        if (error === invalidCsrfTokenError) {
            res.status(403).json({
                error: 'csrf validation error'
            });
        } else {
            next();
        }
    };

    // Middleware chain 2 of 2
    app.use(doubleCsrfProtection, csrfErrorHandler);

    // helmet configuration / Prevent XSS-Filter, X-Frame-Options, Insecure CSP, hide PoweredBy, X-Permitted-Cross-Domain-Policies
    app.use(helmet({xssFilter: false}));                         // Prevent XSS-Filter
    app.use(helmet.frameguard({action: 'deny'}));                // Prevent X-Frame-Options
    app.use(helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", '*.jquery.com', '*.jsdelivr.net', '*.bootstrapcdn.com', '*.cdn.tiny.cloud', 'https://cdn.tiny.cloud', 'https://sp.tinymce.com'],
            objectSrc: ["'none'"],
            imgSrc: ["'self'", 'data:', 'https://bslapps.s3-ap-southeast-1.amazonaws.com', 'https://cdn.tiny.cloud', 'https://sp.tinymce.com/'],
            fontSrc: ["'self'", 'https://cdn.tiny.cloud', 'https://use.fontawesome.com', 'https://sp.tinymce.com']
        },
    }));                                                          // Prevent Insecure Content Security Policy (CSP)
    app.use(helmet.hidePoweredBy());
    app.use(helmet.permittedCrossDomainPolicies({permittedPolicies: 'none'}));  // Prevent Unset/Insecure X-Permitted-Cross-Domain-Policies Header

    // ## ---------------------------------- APP CONFIGURATION ENDS HERE ------------------------------------- ## //

    // routes
    app.get('/csrf-token', (req, res) => {
        return res.json({csrfToken: generateToken(res, req)});
    });

    router.get('/', (req, res) => {
        res.writeHead(301, { "Location": "https://" + req.headers['host'] + '/login' });
        return res.end();
    })

    router.get('/login', (request, response) => {
        fs.readFile(__dirname + '/login.html', function (error, data) {
            if (error) {
                response.writeHead(404);
                response.write(error);
                response.end();
            } else {
                response.writeHead(200, {
                    'Content-Type': 'text/html'
                });
                response.write(data);
                response.end();
            }
        });
    })

    ////////////
    router.post('/api/v1/starconnect', function (req, res) {
        var reqbody = req.body;
        reqbody.datetime = Date.now();
        startrackdb.collection('starconnect').insertOne(reqbody, (err, result) => {
        });
        return res.status(200).send('{"status":"success"}');
    });

    async function mongoAgreegate(req, res) {
        var dealersList = req.body.dealersList;
        if (dealersList == undefined || dealersList.length == 0) {
            return res.status(200).send("[]");
        }
        const pipeline = [
            {
                $match: { "dealerId": { $in: dealersList } }
            }, {
                $sort: { "datetime": -1 }
            }, {
                $group: { "_id": { "dealerId": "$dealerId" }, "record": { $first: "$$ROOT" } }
            }, {
                $project: { "_id": 0, "dealerId": "$record.dealerId", "status": "$record.status", "operationalOn": "$record.operationalOn", "fromtime": "$record.fromtime", "totime": "$record.totime" }
            }
        ];

        const aggCursor = startrackdb.collection('starconnect').aggregate(pipeline);

        var returnList = [];
        await aggCursor.forEach(airbnbListing => {
            returnList.push(airbnbListing);
            console.log(airbnbListing);
        });
        return res.status(200).send(returnList);
    }

    router.post('/api/v1/getDealersStatus', function (req, res) {
        mongoAgreegate(req, res)
    });

    async function mongoAgreegateStarconnect(req, res) {
        var dealerId = req.query["dealerId"];
        if (dealerId == undefined || dealerId == "") {
            return res.status(200).send("{\"status\":\"not found\"}");
        }
        const pipeline = [
            {
                $match: { "dealerId": dealerId }
            }, {
                $sort: { "datetime": -1 }
            }, {
                $group: { "_id": { "dealerId": "$dealerId" }, "record": { $first: "$$ROOT" } }
            }, {
                $project: { "_id": 0, "dealerId": "$record.dealerId", "status": "$record.status", "zone": "$record.zone", "operationalOn": "$record.operationalOn", "bdstCount": "$record.bdstCount", "installationTeamCount": "$record.installationTeamCount", "remarks": "$record.remarks", "fromtime": "$record.fromtime", "totime": "$record.totime", "opforbus": "$record.opforbus", "totsalteam": "$record.totsalteam", "totserteam": "$record.totserteam", "stockInfo": "$record.stockInfo" }
            }
        ];

        const aggCursor = startrackdb.collection('starconnect').aggregate(pipeline);

        var returnObject = {};
        returnObject.status = "not found";
        await aggCursor.forEach(airbnbListing => {
            returnObject = airbnbListing
            console.log(airbnbListing);
        });

        return res.status(200).send(returnObject);
    }

    router.get('/api/v1/getDealerRecord', function (req, res) {
        mongoAgreegateStarconnect(req, res)
    });

    async function mongoAgreegateQlik(req, res) {
        const pipeline = [
            {
                $sort: { "datetime": -1 }
            }, {
                $group: { "_id": { "dealerId": "$dealerId" }, "record": { $first: "$$ROOT" } }
            }, {
                $project: { "_id": 0, "dealerId": "$record.dealerId", "status": "$record.status", "zone": "$record.zone", "operationalOn": "$record.operationalOn", "bdstCount": "$record.bdstCount", "installationTeamCount": "$record.installationTeamCount", "remarks": "$record.remarks" }
            }
        ];

        const aggCursor = startrackdb.collection('starconnect').aggregate(pipeline, { allowDiskUse: true });

        var returnList = [];
        await aggCursor.forEach(airbnbListing => {
            returnList.push(airbnbListing);
        });

        return res.status(200).send(returnList);
    }

    router.get('/api/v1/getAllDealerRecords', function (req, res) {
        mongoAgreegateQlik(req, res)
    });

    ////////////////

    router.post('/performLogin', (request, response) => {
        console.log('Processing login')
        const username = request.body.userId
        const password = request.body.password
        const requestBody = {
            "userId": username,
            "password": password
        }
        fetch(`${AD_LOGIN_BASE_URL}/api/v1/authenticateSerialNumberUser`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body: JSON.stringify(requestBody)
            }).then(response => {
                return response.json()
            }).then(output => {
                if (output.success == "true") {
                    const encryptedCredentials = CryptoJS.AES.encrypt(JSON.stringify(requestBody), AESSecretKey).toString();
                    return response.redirect(`/notification?username=${username}&session=${encryptedCredentials}`)
                }
                else {
                    const message = 'Your username or password is incorrect. Please try again.'
                    return response.redirect(`/login?error=${message}`)
                }
            }).catch(error => {
                return response.status(500).send(`error from server: ${error}`)
            })
    })

    router.get('/notification', (request, response) => {
        const session = request.query.session
        if (!session) {
            response.redirect('/login')
        }
        else {
            fs.readFile(__dirname + "/NotificationBroadcast.html", function (error, data) {
                if (error) {
                    response.writeHead(404);
                    response.write(error);
                    response.end();
                } else {
                    response.writeHead(200, {
                        'Content-Type': 'text/html'
                    });
                    response.write(data);
                    response.end();
                }
            });
        }
    })

    function getDateTimeStr() {
        d = new Date();
        utc = d.getTime() + (d.getTimezoneOffset() * 60000);
        nd = new Date(utc + (3600000 * +5.5));
        return nd.toLocaleString().replace(/,/g, '').replace(/ /g, '-').replace(/\//g, '-');
    }
    router.post('/upload', function (req, res) {

        var remarks = req.query["remarks"];
        if (remarks != undefined && remarks != "") {
            let buff = new Buffer(remarks, 'base64');
            remarks = buff.toString('ascii');
        }

        console.log(remarks);
        const session = req.headers.session
        var bytes = CryptoJS.AES.decrypt(session, AESSecretKey);
        var decryptedUserCredentials = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        console.log(decryptedUserCredentials);

        //decryptedUserCredentials.userId    

        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).send('No files were uploaded.');
        }

        let sampleFile = req.files.myFile;
        let uploadedFileName = req.files.myFile.name

        if (uploadedFileName.endsWith(".csv") == false) {
            return res.status(500).send('File type is not supported');
        }

        console.log(uploadedFileName);
        console.log(sampleFile);

        const savedFileName = decryptedUserCredentials.userId + "_" + getDateTimeStr() + "_" + uploadedFileName;

        sampleFile.mv('/home/ubuntu/Harry/tempfiles/' + savedFileName, function (err) {
            console.log(err);
            if (err)
                return res.status(500).send(err);

            var returnList = [];
            const uploadDate = Date.now();
            fs.createReadStream('/home/ubuntu/Harry/tempfiles/' + savedFileName)
                .pipe(csv())
                .on('data', (row) => {
                    const keys = Object.keys(row);
                    var serialObj = {}
                    serialObj.mCode = row[keys[0]];
                    serialObj.serialNumber = row[keys[1]];
                    serialObj.userId = decryptedUserCredentials.userId;
                    serialObj.uploadDate = uploadDate;
                    serialObj.isException = false;
                    serialObj.remarks = remarks;

                    returnList.push(serialObj);
                })
                .on('end', () => {
                    saveTradedSerialNumbers(returnList, res, decryptedUserCredentials.userId, uploadDate, "file", oAuth2Client);
                    console.log('CSV file successfully processed');
                });
        });
    });

    function saveTradedSerialNumbers(serialNumberList, res, userId, uploadDate, uploadType, auth) {
        console.log(serialNumberList);

        var errorList = [];
        var nonErrorList = [];
        var filteredSerialNumbers = [];
        var serialNumberFoundInManufacturingData = [];
        var serialNumberFoundInTradedData = [];
        var allduplicateserial = [];
        var allduplicateRecord = [];
        var alluniqueRecord = [];
        var uploadedDateStr = getDateStr();
        var uploadedTimeStr = getTimeStr();
        var summaryList = [];
        var csvfilename = "";
        var remarks = "";




        for (srlObj of serialNumberList) {
            srlObj.uploadedDateStr = uploadedDateStr;
            srlObj.uploadedTimeStr = uploadedTimeStr;
            remarks = srlObj.remarks;

            if (srlObj.mCode == undefined || srlObj.mCode == "" || srlObj.serialNumber == undefined || srlObj.serialNumber == "" || srlObj.serialNumber.startsWith(srlObj.mCode) == false) {
                var errorMessage = "Undefined Error";
                if (srlObj.mCode == undefined || srlObj.mCode == "") {
                    errorMessage = "Material Code is blank.";
                }
                else if (srlObj.serialNumber == undefined || srlObj.serialNumber == "") {
                    errorMessage = "Serial number is blank."
                }
                else if (srlObj.serialNumber.startsWith(srlObj.mCode) == false) {
                    errorMessage = "Serial number is not starting with material code."
                }

                errorList.push(srlObj);
                var summaryObj = {};
                summaryObj["Material Code"] = srlObj.mCode;
                summaryObj["Material Serial Number"] = srlObj.serialNumber;
                summaryObj["Status"] = "Error";
                summaryObj["Error Message"] = errorMessage;

                summaryList.push(summaryObj);
            }
            else {
                nonErrorList.push(srlObj);
                filteredSerialNumbers.push(srlObj.serialNumber);
            }
        }

        console.log("filterd" + filteredSerialNumbers);

        var query1 = { sn: { $in: filteredSerialNumbers } };
        var query2 = { serialNumber: { $in: filteredSerialNumbers } };
        serialnumberdb.collection("manufacturingserial").find(query1).toArray(function (err, result) {
            if (result != undefined && result.length > 0) {
                for (robj of result) {
                    serialNumberFoundInManufacturingData.push(robj.sn);
                }
            }
            console.log("manufacfound" + serialNumberFoundInManufacturingData)
            serialnumberdb.collection("indexedtradedserial").find(query2).toArray(function (err, result) {
                if (result != undefined && result.length > 0) {
                    for (robj of result) {
                        serialNumberFoundInTradedData.push(robj.serialNumber);
                    }
                }
                console.log("tradeFound" + serialNumberFoundInTradedData)

                allduplicateserial = serialNumberFoundInManufacturingData + serialNumberFoundInTradedData;
                for (sobj of nonErrorList) {
                    if (allduplicateserial.includes(sobj.serialNumber)) {
                        allduplicateRecord.push(sobj);
                        var summaryObj = {};
                        summaryObj["Material Code"] = sobj.mCode;
                        summaryObj["Material Serial Number"] = sobj.serialNumber;
                        summaryObj["Status"] = "Duplicate";
                        summaryObj["Error Message"] = "This serial number is already present in database."
                        summaryList.push(summaryObj);

                    }
                    else {
                        alluniqueRecord.push(sobj);
                        var summaryObj = {};
                        summaryObj["Material Code"] = sobj.mCode;
                        summaryObj["Material Serial Number"] = sobj.serialNumber;
                        summaryObj["Status"] = "Success";
                        summaryObj["Error Message"] = "";

                        summaryList.push(summaryObj);
                    }
                }
                if (allduplicateRecord.length > 0) {
                    console.log("allduplicaterecords");
                    console.log(allduplicateRecord);
                    serialnumberdb.collection('duplicateRecords').insertMany(allduplicateRecord, (err, result) => {
                    });
                }
                if (alluniqueRecord.length > 0) {
                    console.log("alluniqueRecord");
                    console.log(alluniqueRecord);
                    serialnumberdb.collection('indexedtradedserial').insertMany(alluniqueRecord, (err, result) => {
                    });
                }

                var mObj = {};
                mObj.userId = userId;
                mObj.uploadDate = uploadDate;
                mObj.uploadType = uploadType;
                mObj.erroCount = errorList.length;
                mObj.duplicateCount = allduplicateRecord.length;
                mObj.successUploadCount = alluniqueRecord.length;
                mObj.uploadedDateStr = uploadedDateStr;
                mObj.uploadedTimeStr = uploadedTimeStr;
                mObj.remarks = remarks;


                serialnumberdb.collection('masterserialupload').insertOne(mObj, (err, result) => {
                });

                writeUploadDataIntoGoogleSheet([mObj.uploadDate, mObj.userId, mObj.uploadType, serialNumberList.length, mObj.erroCount, mObj.duplicateCount, mObj.successUploadCount, mObj.uploadedDateStr, mObj.uploadedTimeStr, remarks], auth);

                var returnMessage = "";

                returnMessage = "Total record count = " + (mObj.successUploadCount + mObj.duplicateCount + mObj.erroCount);

                if (mObj.successUploadCount > 0) {
                    returnMessage = returnMessage + ". Successfully uploaded = " + mObj.successUploadCount;
                }

                if (mObj.duplicateCount > 0) {
                    returnMessage = returnMessage + ". Duplicate records = " + mObj.duplicateCount;
                }

                if (mObj.erroCount > 0) {
                    returnMessage = returnMessage + ". Error count = " + mObj.erroCount + "."
                }

                const fields = ['Material Code', 'Material Serial Number', 'Status', 'Error Message'];
                const opts = { fields };

                try {
                    const csv = parse(summaryList, opts);
                    csvfilename = "UploadSummary-" + userId + "-" + getDateTimeStr() + ".csv";
                    fs.writeFile("/home/ubuntu/Harry/uploadedFiles/" + csvfilename, csv, (err) => {
                        sendEmailWithAttachment(userId, csvfilename)
                    });

                } catch (err) {
                    console.error(err);
                }

                const fileURL = "https://sv.bluestarindia.com/uploadedFiles/" + csvfilename;
                returnMessage = returnMessage + " " + "Click <a href=\"" + fileURL + "\" download>here</a> to download summary"

                var returnObj = {};
                returnObj.status = returnMessage;
                return res.status(200).send(returnObj);
            });
        });

    }

    router.post('/generateReport', (request, response) => {
        var month = request.body.month;
        var year = request.body.year;

        if (month == undefined || month == "" || month == null || year == undefined || year == "" || year == null) {
            var returnObj = {};
            returnObj.status = "error";
            returnObj.message = "Year or Month is not selected.";
            return response.status(200).send(returnObj);

        }

        currentMonth = ".*" + "-" + month + "-" + year;
        serialnumberdb.collection("validatedserialnumbers").find({ "validatedOnDate": { '$regex': currentMonth } }).toArray(function (err1, result) {
            if (result.length > 0) {
                saveCSVFile(result, month, year, response);
            }
            else {
                var returnObj = {};
                returnObj.status = "error";
                returnObj.message = "No record found";
                return response.status(200).send(returnObj);

            }
        });
    })

    router.post('/rangeSerialUpload', (request, response) => {
        console.log("range")

        const session = request.headers.session
        var bytes = CryptoJS.AES.decrypt(session, AESSecretKey);
        var decryptedUserCredentials = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        console.log(decryptedUserCredentials);


        const mCode = request.body.mCode
        const fromSerialNumber = request.body.fromSerialNumber
        const toSerialNumber = request.body.toSerialNumber
        const remarks = request.body.remarks;


        if (mCode == undefined || fromSerialNumber == undefined || toSerialNumber == undefined || mCode == "" || fromSerialNumber == "" || toSerialNumber == "") {
            var returnObj = {};
            returnObj.status = "error";
            returnObj.message = "Error in entered values";
            return response.status(200).send(returnObj);
        }

        var fromSerialNumeric = "";
        var fromSerialAlpha = "";
        for (var i = fromSerialNumber.length - 1; i >= 0; i--) {
            if (fromSerialAlpha == "" && fromSerialNumber.charAt(i) >= '0' && fromSerialNumber.charAt(i) <= '9') {
                fromSerialNumeric = fromSerialNumber.charAt(i) + fromSerialNumeric;
            }
            else {
                fromSerialAlpha = fromSerialNumber.charAt(i) + fromSerialAlpha;
            }
        }

        var toSerialNumeric = "";
        var toSerialAlpha = "";
        for (var i = toSerialNumber.length - 1; i >= 0; i--) {
            if (toSerialAlpha == "" && toSerialNumber.charAt(i) >= '0' && toSerialNumber.charAt(i) <= '9') {
                toSerialNumeric = toSerialNumber.charAt(i) + toSerialNumeric;
            }
            else {
                toSerialAlpha = toSerialNumber.charAt(i) + toSerialAlpha;
            }
        }

        var fromNum = Number(fromSerialNumeric)
        var toNum = Number(toSerialNumeric)
        if (fromSerialNumeric.length != toSerialNumeric.length || fromSerialAlpha.length != toSerialAlpha.length || fromNum > toNum || fromSerialAlpha != toSerialAlpha) {
            var returnObj = {};
            returnObj.status = "Error in entered range";
            returnObj.message = "Error in entered range";
            return response.status(200).send(returnObj);
        }

        var returnList = [];
        const uploadDate = Date.now();
        while (fromNum <= toNum) {
            var serialObj = {}
            serialObj.mCode = mCode;
            serialObj.serialNumber = fromSerialAlpha + pad(fromNum, fromSerialNumeric.length);
            serialObj.userId = decryptedUserCredentials.userId;
            serialObj.uploadDate = uploadDate;
            serialObj.isException = false;
            serialObj.remarks = remarks;

            returnList.push(serialObj);
            fromNum++;
        }

        saveTradedSerialNumbers(returnList, response, decryptedUserCredentials.userId, uploadDate, "range", oAuth2Client);

    })

    router.post('/singleSerialUpload', (request, response) => {
        console.log("single")

        const session = request.headers.session
        var bytes = CryptoJS.AES.decrypt(session, AESSecretKey);
        var decryptedUserCredentials = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        console.log(decryptedUserCredentials);


        const mCode = request.body.mCode
        const serialNumber = request.body.serialNumber
        const remarks = request.body.remarks;

        if (mCode == undefined || serialNumber == undefined || mCode == "" || serialNumber == "") {
            var returnObj = {};
            returnObj.status = "Error in entered values";
            returnObj.message = "Error in entered values";
            return response.status(200).send(returnObj);
        }

        var returnList = [];

        var serialNumberList = serialNumber.split(",").map((item) => item.trim());
        serialNumberList = Array.from(new Set(serialNumberList));

        const todaysdate = Date.now();
        for (sn of serialNumberList) {
            var serialObj = {};
            serialObj.mCode = mCode;
            serialObj.serialNumber = sn;
            serialObj.userId = decryptedUserCredentials.userId;
            serialObj.uploadDate = todaysdate;
            serialObj.isException = true;
            serialObj.remarks = remarks;
            returnList.push(serialObj);
        }


        saveTradedSerialNumbers(returnList, response, decryptedUserCredentials.userId, todaysdate, "single", oAuth2Client);

    })

    async function verifyApiKey(request, response, auth,apiType) {
        const apiKey = request.body.apiKey;
        const sheets = google.sheets({ version: 'v4', auth });
        await sheets.spreadsheets.values.get({
            spreadsheetId: '1EHkFNPCawUtKuT-ur_1M49tvtWFGoCIV8LyB1ZBPYl0',
            range: 'VendorKeys!A2:B',
        }, async (err, res) => {
            if (err) {
                var returnObj = {};
                returnObj.responseStatus = "-3";
                returnObj.responseMessage = "Server Error";
                return response.status(200).send(returnObj);
            }

            const rows = res.data.values;
            var apikeyfound = false;
            var channelPartnerName = "";
            if (rows.length) {
                for (row of rows) {
                    if (apiKey === row[0]) {
                        apikeyfound = true;
                        channelPartnerName = row[1];
                        break;
                    }
                }
            }
            if (apikeyfound) {
                if(apiType == 0)
                {
                    validateSerialNumber(request, response, auth, channelPartnerName)
                }
                else if(apiType == 1)
                {
                    searchSerialNumberNew(request, response)
                }
            }
            else {
                var returnObj = {};
                returnObj.responseStatus = "-3";
                returnObj.responseMessage = "Server Error";
                return response.status(200).send(returnObj);
            }

        });
    }

    async function verifyApiKeyNew(request, response, auth,apiType) {

        console.log("In verify method")
        const apiKey = request.body.apiKey;
        const sheets = google.sheets({ version: 'v4', auth });
        await sheets.spreadsheets.values.get({
            spreadsheetId: '1EHkFNPCawUtKuT-ur_1M49tvtWFGoCIV8LyB1ZBPYl0',
            range: 'VendorKeys!A2:B',
        }, async (err, res) => {
            if (err) {
                var returnObj = {};
                returnObj.responseStatus = "-3";
                returnObj.responseMessage = "Server Error";
                return response.status(200).send(returnObj);
            }

            const rows = res.data.values;
            var apikeyfound = false;
            var channelPartnerName = "";
            if (rows.length) {
                for (row of rows) {
                   // console.log(row);
                    if (apiKey === row[0]) {
                        apikeyfound = true;
                        channelPartnerName = row[1];
                        break;
                    }
                }
            }
            if (apikeyfound) {
                if(apiType == 0)
                {
                    validateSerialNumberNew(request, response, auth, channelPartnerName)
                }
                else if(apiType == 1)
                {
                    searchSerialNumberNew(request, response)
                }
            }
            else {
                var returnObj = {};
                returnObj.responseStatus = "-3";
                returnObj.responseMessage = "Server Error";
                return response.status(200).send(returnObj);
            }

        });
    }

    function getTimeStr() {

        return moment().tz("Asia/Kolkata").format('HH:mm:ss');
    }

    function getDateStr() {

        return moment().tz("Asia/Kolkata").format('DD-MM-YYYY');


    }

    function saveRejectedSerialNumbers(serialNumber, rejectedDate, rejectedTime, apiKey, channelPartnerName, reason) {
        var query = { serialNumber: serialNumber, rejectedDate: rejectedDate, rejectedTime: rejectedTime, apiKey: apiKey, channelPartnerName: channelPartnerName, reasonToReject: reason };
        serialnumberdb.collection('rejectedserialnumbers').insertOne(query, (err, result) => {
        });
    }

    function validateSerialNumber(request, res, auth, channelPartnerName) {
        var materialCode = "";
        var serialNumber = request.body.serialNumber;
        const apiKey = request.body.apiKey;

        var formattedDate = getDateStr();
        var formattedTime = getTimeStr();

        var uploadedBy = "";
        var uploadedDate = "";
        var uploadedTime = "";


        if (serialNumber.length >= 4 && serialNumber.startsWith("S/N:")) {
            serialNumber = serialNumber.substring(4, str.length - 1);
        }

        var cfcResult;
        if (request.body.cfcNumber != null && request.body.cfcNumber != undefined) {
            // serialnumberdb.collection("CFCNumber").find({cfcNumber:request.body.cfcNumber}).sort({createdAt:-1}).toArray(function (err7, result7) {

            serialnumberdb.collection("CFCNumber").find({cfcNumber:request.body.cfcNumber}).sort({createdAt:-1}).toArray(function (err7, result7) {
                if (result7 == undefined || result7 == null || result7.length == 0) {
                    var returnObj = {}
                    returnObj.responseStatus = "-5"
                    returnObj.responseMessage = "CFCNumber is unknown"
                    return res.status(200).send(returnObj)
                } else {
                    var date = new Date()
                    var currentTime = date.getTime()
                    var record = result7[0]
                    var createdAt = record.createdAt
                    var timeDifference = currentTime - createdAt

                    if(timeDifference > (60*60*1000)) {
                        var obj = {}
                        obj.responseStatus = "-6"
                        obj.responseMessage = "CFC validity expired."
                        return res.status(200).send(obj);    
                    } else {
                        // var count = serialnumberdb.collection("validatedserialnumbers").find({"cfcNumber":request.body.cfcNumber,"validatedByAPIKey":apiKey}).toArray()
                        // console.log("Count = ",count.length)
                        serialnumberdb.collection("SerialNumberWithCFC").find({"cfcNumber":request.body.cfcNumber,"apiKey":apiKey}).toArray(function (err3, result3) {
                            console.log("Result3 = ",result3.length)
                            if (result3.length > 1) {
                                var returnObj = {}
                                returnObj.responseStatus = "-6"
                                returnObj.responseMessage = "CFC verification limit exceeded."
                                return res.status(200).send(returnObj); 
                            } else {
                                cfcResult = result7

                                serialnumberdb.collection("blockedserialnumbers").findOne({ sn: serialNumber }, function (err5, result5) {
                                    if (result5 != undefined && result5 != null) {
                                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number is blocked");
                                        var returnObj = {};
                                        returnObj.responseStatus = "-1";
                                        returnObj.responseMessage = "Invalid Serial Number";
                                        return res.status(200).send(returnObj);
                                    }
                        
                                    serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
                                        if (result != undefined && result != null) {
                                            var date = new Date();
                                            date.setDate(date.getDate()-2);
                                            var timestamp = date.getTime();
                                            serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber,updatedAt:{$lt:timestamp}}, function(err2, result2){
                                                if (result2 != undefined && result2 != null) {
                                                    serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                                        if (result != undefined && result != null) {
                                    
                                                            materialCode = result.mc;
                                                            var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                                            if(cfcResult != null) {
                                                                query["cfcNumber"] = cfcResult.cfcNumber
                                                            }
                                                            serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                            });
                                    
                                                            if (cfcResult != undefined && cfcResult != null) {
                                                                var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                })
                                                            }
                                    
                                                            writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                                    
                                                            var returnObj = {};
                                                            returnObj.responseStatus = "0";
                                                            returnObj.responseMessage = "Valid Serial Number";
                                                            return res.status(200).send(returnObj);
                                                        }
                                    
                                                        serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                                            if (result != undefined && result != null) {
                                    
                                                                materialCode = result.mCode;
                                                                uploadedBy = result.userId;
                                                                uploadedDate = result.uploadedDateStr;
                                                                uploadedTime = result.uploadedTimeStr;
                                                                remarks = result.remarks;
                                    
                                                                var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                                if(cfcResult != null) {
                                                                    query["cfcNumber"] = cfcResult.cfcNumber
                                                                }
                                                                serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                                });
                                    
                                                                if (cfcResult != undefined && cfcResult != null) {
                                                                    var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                    serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                    })
                                                                }
                                    
                                                                writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                                var returnObj = {};
                                                                returnObj.responseStatus = "0";
                                                                returnObj.responseMessage = "Valid Serial Number";
                                                                return res.status(200).send(returnObj);
                                                            }
                                                            saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                                            var returnObj = {};
                                                            returnObj.responseStatus = "-1";
                                                            returnObj.responseMessage = "Invalid Serial Number";
                                                            return res.status(200).send(returnObj);
                                    
                                                        });
                                                    });
                                                } else {
                                                    saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number already validated");
                                                    var returnObj = {};
                                                    returnObj.responseStatus = "-2";
                                                    returnObj.responseMessage = "Serial Number already validated";
                                                    return res.status(200).send(returnObj);
                                                }
                                            })
                                        } else {
                                            serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                                if (result != undefined && result != null) {
                            
                                                    materialCode = result.mc;
                                                    var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                                    if(cfcResult != null) {
                                                        query["cfcNumber"] = cfcResult.cfcNumber
                                                    }
                                                    serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                    });
                            
                                                    if (cfcResult != undefined && cfcResult != null) {
                                                        var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                        serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                        })
                                                    }
                            
                                                    writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                            
                                                    var returnObj = {};
                                                    returnObj.responseStatus = "0";
                                                    returnObj.responseMessage = "Valid Serial Number";
                                                    return res.status(200).send(returnObj);
                                                }
                            
                                                serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                                    if (result != undefined && result != null) {
                            
                                                        materialCode = result.mCode;
                                                        uploadedBy = result.userId;
                                                        uploadedDate = result.uploadedDateStr;
                                                        uploadedTime = result.uploadedTimeStr;
                                                        remarks = result.remarks;
                            
                                                        var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                        if(cfcResult != null) {
                                                            query["cfcNumber"] = cfcResult.cfcNumber
                                                        }
                                                        serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                        });
                            
                                                        if (cfcResult != undefined && cfcResult != null) {
                                                            var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                            serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                            })
                                                        }
                            
                                                        writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                        var returnObj = {};
                                                        returnObj.responseStatus = "0";
                                                        returnObj.responseMessage = "Valid Serial Number";
                                                        return res.status(200).send(returnObj);
                                                    }
                                                    saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                                    var returnObj = {};
                                                    returnObj.responseStatus = "-1";
                                                    returnObj.responseMessage = "Invalid Serial Number";
                                                    return res.status(200).send(returnObj);
                            
                                                });
                                            });
                                        }
                                    });
                                });
                            }
                        })
                    }
                }
            })
        } else {
            serialnumberdb.collection("blockedserialnumbers").findOne({ sn: serialNumber }, function (err5, result5) {
                if (result5 != undefined && result5 != null) {
                    saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number is blocked");
                    var returnObj = {};
                    returnObj.responseStatus = "-1";
                    returnObj.responseMessage = "Invalid Serial Number";
                    return res.status(200).send(returnObj);
                }
    
                console.log("serial number",serialNumber);

                serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
                    if (result != undefined && result != null) {
                        console.log("number found in validatedserialnumbers");
                        var oldDate = new Date();
                        oldDate.setDate(oldDate.getDate()-2);
                        var timestamp = oldDate.getTime();
                        serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber,updatedAt:{$gt:timestamp}}, function(err2, result2){
                            if (result2 != undefined && result2 != null) {
                                serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                    if (result != undefined && result != null) {
                
                                        materialCode = result.mc;
                                        var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                        serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                        });
                
                                        writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                
                                        var returnObj = {};
                                        returnObj.responseStatus = "0";
                                        returnObj.responseMessage = "Valid Serial Number";
                                        return res.status(200).send(returnObj);
                                    }
                
                                    serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                        if (result != undefined && result != null) {
                
                                            materialCode = result.mCode;
                                            uploadedBy = result.userId;
                                            uploadedDate = result.uploadedDateStr;
                                            uploadedTime = result.uploadedTimeStr;
                                            remarks = result.remarks;
                
                                            var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                            serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                            });
                
                                            writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                            var returnObj = {};
                                            returnObj.responseStatus = "0";
                                            returnObj.responseMessage = "Valid Serial Number";
                                            return res.status(200).send(returnObj);
                                        }
                                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                        var returnObj = {};
                                        returnObj.responseStatus = "-1";
                                        returnObj.responseMessage = "Invalid Serial Number";
                                        return res.status(200).send(returnObj);
                
                                    });
                                });
                            } else {
                                saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number already validated");
                                var returnObj = {};
                                returnObj.responseStatus = "-2";
                                returnObj.responseMessage = "Serial Number already validated";
                                return res.status(200).send(returnObj);
                            }
                        })
                    } else {
                        console.log("number checking in else part");
                        serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {

                            console.log("manufacturingserial result",result);

                             if (result != undefined && result != null) {
        
                                materialCode = result.mc;
                                var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                });
        
                                writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
        
                                var returnObj = {};
                                returnObj.responseStatus = "0";
                                returnObj.responseMessage = "Valid Serial Number";
                                return res.status(200).send(returnObj);
                            }
        
                            serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                
                                console.log("indexedtradedserial result",result);

                                if (result != undefined && result != null) {
        
                                    materialCode = result.mCode;
                                    uploadedBy = result.userId;
                                    uploadedDate = result.uploadedDateStr;
                                    uploadedTime = result.uploadedTimeStr;
                                    remarks = result.remarks;
        
                                    var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                    serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                    });
        
                                    writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                    var returnObj = {};
                                    returnObj.responseStatus = "0";
                                    returnObj.responseMessage = "Valid Serial Number";
                                    return res.status(200).send(returnObj);
                                }

                                console.log("serial number not found in db");
                                saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                var returnObj = {};
                                returnObj.responseStatus = "-1";
                                returnObj.responseMessage = "Invalid Serial Number";
                                return res.status(200).send(returnObj);
        
                            });
                        });
                    }
                });
            });
        }
    }

    // Method for pinelabs 
    function validateSerialNumberNew(request, res, auth, channelPartnerName) {
        var materialCode = "";
        var serialNumber = request.body.serialNumber;
        var onlyVaidate = request.body.only_validate;
        const apiKey = request.body.apiKey;

        var formattedDate = getDateStr();
        var formattedTime = getTimeStr();

        var uploadedBy = "";
        var uploadedDate = "";
        var uploadedTime = "";


        if (serialNumber.length >= 4 && serialNumber.startsWith("S/N:")) {
            serialNumber = serialNumber.substring(4, str.length - 1);
        }

        var cfcResult;

        if (onlyVaidate != null && onlyVaidate != undefined) {
          if (onlyVaidate=="false"){
            var query = { sn: serialNumber };
            serialnumberdb.collection("blockedserialnumbers").findOne({ sn: serialNumber }, function (err5, result5) {
                if (result5 != undefined && result5 != null) {
                    var returnObj = {};
                    returnObj.responseStatus = "-2";
                    returnObj.responseMessage = "Serial number is already blocked";
                    return res.status(200).send(returnObj);
                }else{
                    serialnumberdb.collection("validatedserialnumbers").findOne({serialNumber:serialNumber}, function(err1, result) {
                        if (result != undefined && result != null) {
                            serialnumberdb.collection('blockedserialnumbers').insertOne(query, (err, result) => {
                                if (err) {
                                    console.log("Error = ",err)
                                } else {
                                    var returnObj = {};
                                        returnObj.responseStatus = "0";
                                        returnObj.responseMessage = "Serial number is blocked successfully";
                                        return res.status(200).send(returnObj);
                                }
                            });
                        }else{
                            var returnObj = {};
                            returnObj.responseStatus = "-1";
                            returnObj.responseMessage = "Invalid Serial Number";
                            console.log("Response = ",returnObj);
                            return res.status(200).send(returnObj);
                        }
                    })
                    
                } 
            })
          }else{
            if (request.body.cfcNumber != null && request.body.cfcNumber != undefined) {
                serialnumberdb.collection("CFCNumber").findOne({cfcNumber:request.body.cfcNumber}, function(err7, result7) {
                    if (result7 == undefined || result7 == null) {
                        var returnObj = {}
                        returnObj.responseStatus = "-5"
                        returnObj.responseMessage = "CFCNumber is unknown"
                        return res.status(200).send(returnObj)
                    } else {
                        var date = new Date()
                        var currentTime = date.getTime()
                        var createdAt = result7.createdAt
                        var timeDifference = currentTime - createdAt
    
                        if(timeDifference > (60*60*1000)) {
                            var obj = {}
                            obj.responseStatus = "-6"
                            obj.responseMessage = "CFC validity expired."
                            return res.status(200).send(obj);    
                        } else {
                            // var count = serialnumberdb.collection("validatedserialnumbers").find({"cfcNumber":request.body.cfcNumber,"validatedByAPIKey":apiKey}).toArray()
                            // console.log("Count = ",count.length)
                            serialnumberdb.collection("SerialNumberWithCFC").find({"cfcNumber":request.body.cfcNumber,"apiKey":apiKey}).toArray(function (err3, result3) {
                                console.log("Result3 = ",result3.length)
                                if (result3.length > 1) {
                                    var returnObj = {}
                                    returnObj.responseStatus = "-6"
                                    returnObj.responseMessage = "CFC verification limit exceeded."
                                    return res.status(200).send(returnObj); 
                                } else {
                                    cfcResult = result7
    
                                    serialnumberdb.collection("blockedserialnumbers").findOne({ sn: serialNumber }, function (err5, result5) {
                                        if (result5 != undefined && result5 != null) {
                                            saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number is blocked");
                                            var returnObj = {};
                                            returnObj.responseStatus = "-1";
                                            returnObj.responseMessage = "Serial number is blocked";
                                            return res.status(200).send(returnObj);
                                        }
                            
                                        serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
                                            if (result != undefined && result != null) {
                                                var date = new Date();
                                                date.setDate(date.getDate()-2);
                                                var timestamp = date.getTime();
                                                serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber,updatedAt:{$lt:timestamp}}, function(err2, result2){
                                                    if (result2 != undefined && result2 != null) {
                                                        serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                                            if (result != undefined && result != null) {
                                        
                                                                materialCode = result.mc;
                                                                var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                                                if(cfcResult != null) {
                                                                    query["cfcNumber"] = cfcResult.cfcNumber
                                                                }
                                                                serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                                });
                                        
                                                                if (cfcResult != undefined && cfcResult != null) {
                                                                    var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                    serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                    })
                                                                }
                                        
                                                                writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                                        
                                                                var returnObj = {};
                                                                returnObj.responseStatus = "0";
                                                                returnObj.responseMessage = "Valid Serial Number";
                                                                return res.status(200).send(returnObj);
                                                            }
                                        
                                                            serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                                                if (result != undefined && result != null) {
                                        
                                                                    materialCode = result.mCode;
                                                                    uploadedBy = result.userId;
                                                                    uploadedDate = result.uploadedDateStr;
                                                                    uploadedTime = result.uploadedTimeStr;
                                                                    remarks = result.remarks;
                                        
                                                                    var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                                    if(cfcResult != null) {
                                                                        query["cfcNumber"] = cfcResult.cfcNumber
                                                                    }
                                                                    serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                                    });
                                        
                                                                    if (cfcResult != undefined && cfcResult != null) {
                                                                        var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                        serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                        })
                                                                    }
                                        
                                                                    writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                                    var returnObj = {};
                                                                    returnObj.responseStatus = "0";
                                                                    returnObj.responseMessage = "Valid Serial Number";
                                                                    return res.status(200).send(returnObj);
                                                                }
                                                                saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                                                var returnObj = {};
                                                                returnObj.responseStatus = "-1";
                                                                returnObj.responseMessage = "Invalid Serial Number";
                                                                return res.status(200).send(returnObj);
                                        
                                                            });
                                                        });
                                                    } else {
                                                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number already validated");
                                                        var returnObj = {};
                                                        returnObj.responseStatus = "201";
                                                        returnObj.responseMessage = "Serial Number already validated";
                                                        return res.status(200).send(returnObj);
                                                    }
                                                })
                                            } else {
                                                serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                                    if (result != undefined && result != null) {
                                
                                                        materialCode = result.mc;
                                                        var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                                        if(cfcResult != null) {
                                                            query["cfcNumber"] = cfcResult.cfcNumber
                                                        }
                                                        serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                        });
                                
                                                        if (cfcResult != undefined && cfcResult != null) {
                                                            var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                            serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                            })
                                                        }
                                
                                                        writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                                
                                                        var returnObj = {};
                                                        returnObj.responseStatus = "0";
                                                        returnObj.responseMessage = "Valid Serial Number";
                                                        return res.status(200).send(returnObj);
                                                    }
                                
                                                    serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                                        if (result != undefined && result != null) {
                                
                                                            materialCode = result.mCode;
                                                            uploadedBy = result.userId;
                                                            uploadedDate = result.uploadedDateStr;
                                                            uploadedTime = result.uploadedTimeStr;
                                                            remarks = result.remarks;
                                
                                                            var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                            if(cfcResult != null) {
                                                                query["cfcNumber"] = cfcResult.cfcNumber
                                                            }
                                                            serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                            });
                                
                                                            if (cfcResult != undefined && cfcResult != null) {
                                                                var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                })
                                                            }
                                
                                                            writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                            var returnObj = {};
                                                            returnObj.responseStatus = "0";
                                                            returnObj.responseMessage = "Valid Serial Number";
                                                            return res.status(200).send(returnObj);
                                                        }
                                                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                                        var returnObj = {};
                                                        returnObj.responseStatus = "-1";
                                                        returnObj.responseMessage = "Invalid Serial Number";
                                                        return res.status(200).send(returnObj);
                                
                                                    });
                                                });
                                            }
                                        });
                                    });
                                }
                            })
                        }
                    }
                })
            } else {
                console.log("In else part")
                serialnumberdb.collection("blockedserialnumbers").findOne({ sn: serialNumber }, function (err5, result5) {
                    if (result5 != undefined && result5 != null) {
                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number is blocked");
                        var returnObj = {};
                        returnObj.responseStatus = "-1";
                        returnObj.responseMessage = "Serial number is blocked";
                        return res.status(200).send(returnObj);
                    }
        
                    serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
                       console.log("search result",result);
                        if (result != undefined && result != null) {
                            var oldDate = new Date();
                            oldDate.setDate(oldDate.getDate()-2);
                            var timestamp = oldDate.getTime();
                            serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber,updatedAt:{$gt:timestamp}}, function(err2, result2){
                                if (result2 != undefined && result2 != null) {
                                    serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                        if (result != undefined && result != null) {   
                                            materialCode = result.mc;
                                            var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                            serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                            });
                    
                                            writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                    
                                            var returnObj = {};
                                            returnObj.responseStatus = "0";
                                            returnObj.responseMessage = "Valid Serial Number";
                                            return res.status(200).send(returnObj);
                                        }
                    
                                        serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                            if (result != undefined && result != null) {
                    
                                                materialCode = result.mCode;
                                                uploadedBy = result.userId;
                                                uploadedDate = result.uploadedDateStr;
                                                uploadedTime = result.uploadedTimeStr;
                                                remarks = result.remarks;
                    
                                                var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                });
                    
                                                writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                var returnObj = {};
                                                returnObj.responseStatus = "0";
                                                returnObj.responseMessage = "Valid Serial Number";
                                                return res.status(200).send(returnObj);
                                            }
                                            saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                            var returnObj = {};
                                            returnObj.responseStatus = "-1";
                                            returnObj.responseMessage = "Invalid Serial Number";
                                            return res.status(200).send(returnObj);
                    
                                        });
                                    });
                                } else {
                                    saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number already validated");
                                    var returnObj = {};
                                    returnObj.responseStatus = "201";
                                    returnObj.responseMessage = "Serial Number already validated";
                                    return res.status(200).send(returnObj);
                                }
                            })
                        } else {
                            serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                if (result != undefined && result != null) {
            
                                    materialCode = result.mc;
                                    var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                    serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                    });
            
                                    writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
            
                                    var returnObj = {};
                                    returnObj.responseStatus = "0";
                                    returnObj.responseMessage = "Valid Serial Number";
                                    return res.status(200).send(returnObj);
                                }
            
                                serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                    if (result != undefined && result != null) {
            
                                        materialCode = result.mCode;
                                        uploadedBy = result.userId;
                                        uploadedDate = result.uploadedDateStr;
                                        uploadedTime = result.uploadedTimeStr;
                                        remarks = result.remarks;
            
                                        var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                        serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                        });
            
                                        writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                        var returnObj = {};
                                        returnObj.responseStatus = "0";
                                        returnObj.responseMessage = "Valid Serial Number";
                                        return res.status(200).send(returnObj);
                                    }
                                    saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                    var returnObj = {};
                                    returnObj.responseStatus = "-1";
                                    returnObj.responseMessage = "Invalid Serial Number";
                                    return res.status(200).send(returnObj);
            
                                });
                            });
                        }
                    });
                });
            } 
          }
        }else{
            if (request.body.cfcNumber != null && request.body.cfcNumber != undefined) {
                serialnumberdb.collection("CFCNumber").findOne({cfcNumber:request.body.cfcNumber}, function(err7, result7) {
                    if (result7 == undefined || result7 == null) {
                        var returnObj = {}
                        returnObj.responseStatus = "-5"
                        returnObj.responseMessage = "CFCNumber is unknown"
                        return res.status(200).send(returnObj)
                    } else {
                        var date = new Date()
                        var currentTime = date.getTime()
                        var createdAt = result7.createdAt
                        var timeDifference = currentTime - createdAt
    
                        if(timeDifference > (60*60*1000)) {
                            var obj = {}
                            obj.responseStatus = "-6"
                            obj.responseMessage = "CFC validity expired."
                            return res.status(200).send(obj);    
                        } else {
                            // var count = serialnumberdb.collection("validatedserialnumbers").find({"cfcNumber":request.body.cfcNumber,"validatedByAPIKey":apiKey}).toArray()
                            // console.log("Count = ",count.length)
                            serialnumberdb.collection("SerialNumberWithCFC").find({"cfcNumber":request.body.cfcNumber,"apiKey":apiKey}).toArray(function (err3, result3) {
                                console.log("Result3 = ",result3.length)
                                if (result3.length > 1) {
                                    var returnObj = {}
                                    returnObj.responseStatus = "-6"
                                    returnObj.responseMessage = "CFC verification limit exceeded."
                                    return res.status(200).send(returnObj); 
                                } else {
                                    cfcResult = result7
    
                                    serialnumberdb.collection("blockedserialnumbers").findOne({ sn: serialNumber }, function (err5, result5) {
                                        if (result5 != undefined && result5 != null) {
                                            saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number is blocked");
                                            var returnObj = {};
                                            returnObj.responseStatus = "-1";
                                            returnObj.responseMessage = "Invalid Serial Number";
                                            return res.status(200).send(returnObj);
                                        }
                            
                                        serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
                                            if (result != undefined && result != null) {
                                                var date = new Date();
                                                date.setDate(date.getDate()-2);
                                                var timestamp = date.getTime();
                                                serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber,updatedAt:{$lt:timestamp}}, function(err2, result2){
                                                    if (result2 != undefined && result2 != null) {
                                                        serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                                            if (result != undefined && result != null) {
                                        
                                                                materialCode = result.mc;
                                                                var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                                                if(cfcResult != null) {
                                                                    query["cfcNumber"] = cfcResult.cfcNumber
                                                                }
                                                                serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                                });
                                        
                                                                if (cfcResult != undefined && cfcResult != null) {
                                                                    var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                    serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                    })
                                                                }
                                        
                                                                writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                                        
                                                                var returnObj = {};
                                                                returnObj.responseStatus = "0";
                                                                returnObj.responseMessage = "Valid Serial Number";
                                                                return res.status(200).send(returnObj);
                                                            }
                                        
                                                            serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                                                if (result != undefined && result != null) {
                                        
                                                                    materialCode = result.mCode;
                                                                    uploadedBy = result.userId;
                                                                    uploadedDate = result.uploadedDateStr;
                                                                    uploadedTime = result.uploadedTimeStr;
                                                                    remarks = result.remarks;
                                        
                                                                    var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                                    if(cfcResult != null) {
                                                                        query["cfcNumber"] = cfcResult.cfcNumber
                                                                    }
                                                                    serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                                    });
                                        
                                                                    if (cfcResult != undefined && cfcResult != null) {
                                                                        var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                        serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                        })
                                                                    }
                                        
                                                                    writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                                    var returnObj = {};
                                                                    returnObj.responseStatus = "0";
                                                                    returnObj.responseMessage = "Valid Serial Number";
                                                                    return res.status(200).send(returnObj);
                                                                }
                                                                saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                                                var returnObj = {};
                                                                returnObj.responseStatus = "-1";
                                                                returnObj.responseMessage = "Invalid Serial Number";
                                                                return res.status(200).send(returnObj);
                                        
                                                            });
                                                        });
                                                    } else {
                                                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number already validated");
                                                        var returnObj = {};
                                                        returnObj.responseStatus = "-2";
                                                        returnObj.responseMessage = "Serial Number already validated";
                                                        return res.status(200).send(returnObj);
                                                    }
                                                })
                                            } else {
                                                serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                                    if (result != undefined && result != null) {
                                
                                                        materialCode = result.mc;
                                                        var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                                        if(cfcResult != null) {
                                                            query["cfcNumber"] = cfcResult.cfcNumber
                                                        }
                                                        serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                        });
                                
                                                        if (cfcResult != undefined && cfcResult != null) {
                                                            var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                            serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                            })
                                                        }
                                
                                                        writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                                
                                                        var returnObj = {};
                                                        returnObj.responseStatus = "0";
                                                        returnObj.responseMessage = "Valid Serial Number";
                                                        return res.status(200).send(returnObj);
                                                    }
                                
                                                    serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                                        if (result != undefined && result != null) {
                                
                                                            materialCode = result.mCode;
                                                            uploadedBy = result.userId;
                                                            uploadedDate = result.uploadedDateStr;
                                                            uploadedTime = result.uploadedTimeStr;
                                                            remarks = result.remarks;
                                
                                                            var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                            if(cfcResult != null) {
                                                                query["cfcNumber"] = cfcResult.cfcNumber
                                                            }
                                                            serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                            });
                                
                                                            if (cfcResult != undefined && cfcResult != null) {
                                                                var query1 = {cfcNumber:cfcResult.cfcNumber, modelCode:materialCode, mobileNumber:cfcResult.mobileNumber, serialNumber:serialNumber, createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:channelPartnerName,apiKey:apiKey}
                                                                serialnumberdb.collection("SerialNumberWithCFC").updateOne({serialNumber:serialNumber},{$set:query1},{upsert:true},(err2,result2)=>{
                                                                })
                                                            }
                                
                                                            writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                            var returnObj = {};
                                                            returnObj.responseStatus = "0";
                                                            returnObj.responseMessage = "Valid Serial Number";
                                                            return res.status(200).send(returnObj);
                                                        }
                                                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                                        var returnObj = {};
                                                        returnObj.responseStatus = "-1";
                                                        returnObj.responseMessage = "Invalid Serial Number";
                                                        return res.status(200).send(returnObj);
                                
                                                    });
                                                });
                                            }
                                        });
                                    });
                                }
                            })
                        }
                    }
                })
            } else {
                console.log("wihout CFC code")
                serialnumberdb.collection("blockedserialnumbers").findOne({ sn: serialNumber }, function (err5, result5) {
                    if (result5 != undefined && result5 != null) {
                        console.log("blocked serial number");
                        saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number is blocked");
                        var returnObj = {};
                        returnObj.responseStatus = "-1";
                        returnObj.responseMessage = "Invalid Serial Number";
                        return res.status(200).send(returnObj);
                    }
                    serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
                        if (result != undefined && result != null) {
                            var oldDate = new Date();
                            oldDate.setDate(oldDate.getDate()-2);
                            var timestamp = oldDate.getTime();
                            console.log("checking in unblock list");
                            serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber,updatedAt:{$gt:timestamp}}, function(err2, result2){
                                if (result2 != undefined && result2 != null) {
                                    console.log("found in unblock list");
                                    serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                        if (result != undefined && result != null) {
                    
                                            materialCode = result.mc;
                                            var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                            serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                            });
                    
                                            writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
                    
                                            var returnObj = {};
                                            returnObj.responseStatus = "0";
                                            returnObj.responseMessage = "Valid Serial Number";
                                            return res.status(200).send(returnObj);
                                        }
                    
                                        serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                            if (result != undefined && result != null) {
                    
                                                materialCode = result.mCode;
                                                uploadedBy = result.userId;
                                                uploadedDate = result.uploadedDateStr;
                                                uploadedTime = result.uploadedTimeStr;
                                                remarks = result.remarks;
                    
                                                var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                                serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                                });
                    
                                                writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                                var returnObj = {};
                                                returnObj.responseStatus = "0";
                                                returnObj.responseMessage = "Valid Serial Number";
                                                return res.status(200).send(returnObj);
                                            }
                                            saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                            var returnObj = {};
                                            returnObj.responseStatus = "-1";
                                            returnObj.responseMessage = "Invalid Serial Number";
                                            return res.status(200).send(returnObj);
                    
                                        });
                                    });
                                } else {
                                    saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Serial Number already validated");
                                    var returnObj = {};
                                    returnObj.responseStatus = "-2";
                                    returnObj.responseMessage = "Serial Number is already validated";
                                    return res.status(200).send(returnObj);
                                }
                            })
                        } else {
                            serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                                if (result != undefined && result != null) {
            
                                    materialCode = result.mc;
                                    var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "manufacturing", isException: false, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: "" };
                                    serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                    });
            
                                    writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "manufacturing", false, uploadedBy, uploadedDate, uploadedTime, ""], auth)
            
                                    var returnObj = {};
                                    returnObj.responseStatus = "0";
                                    returnObj.responseMessage = "Valid Serial Number";
                                    return res.status(200).send(returnObj);
                                }
            
                                serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                                    if (result != undefined && result != null) {
            
                                        materialCode = result.mCode;
                                        uploadedBy = result.userId;
                                        uploadedDate = result.uploadedDateStr;
                                        uploadedTime = result.uploadedTimeStr;
                                        remarks = result.remarks;
            
                                        var query = { serialNumber: serialNumber, materialCode: materialCode, validatedOnDate: formattedDate, validatedOnTime: formattedTime, validatedByAPIKey: apiKey, validatedByName: channelPartnerName, serialNumberType: "traded", isException: result.isException, uploadedBy: uploadedBy, uploadedDate: uploadedDate, uploadedTime: uploadedTime, remarks: remarks };
                                        serialnumberdb.collection('validatedserialnumbers').insertOne(query, (err, result) => {
                                        });
            
                                        writeValidateDataIntoGoogleSheet([serialNumber, materialCode, formattedDate, formattedTime, apiKey, channelPartnerName, "traded", result.isException, uploadedBy, uploadedDate, uploadedTime, remarks], auth)
                                        var returnObj = {};
                                        returnObj.responseStatus = "0";
                                        returnObj.responseMessage = "Valid Serial Number";
                                        return res.status(200).send(returnObj);
                                    }
                                    saveRejectedSerialNumbers(serialNumber, formattedDate, formattedTime, apiKey, channelPartnerName, "Invalid Serial Number");
                                    var returnObj = {};
                                    returnObj.responseStatus = "-1";
                                    returnObj.responseMessage = "Invalid Serial Number";
                                    return res.status(200).send(returnObj);
            
                                });
                            });
                        }
                    });
                });
            }
        }
    }

    function saveCSVFile(resultArray, month, year, response) {
        var newResultList = [];
        var returnMessage = "";
        returnMessage = resultArray.length + " Records Found.";
        for (resultObj of resultArray) {
            var newResultObj = {};
            newResultObj["Material Code"] = resultObj.materialCode;
            newResultObj["Material Serial Number"] = resultObj.serialNumber;
            newResultObj["Validated By Channel Finance Co"] = resultObj.validatedByName;
            newResultObj["Validation Done On"] = resultObj.validatedOnDate;
            newResultObj["Validation Time"] = resultObj.validatedOnTime;
            newResultObj["Uploaded By User ID"] = resultObj.uploadedBy;
            newResultObj["Uploaded On"] = resultObj.uploadedDate;
            newResultObj["Category"] = resultObj.serialNumberType;

            if (resultObj.isException == false) {
                newResultObj["Exception Upload"] = "";
            }
            else {
                newResultObj["Exception Upload"] = "E";
            }
            newResultList.push(newResultObj);
        }

        const fields = ['Material Code', 'Material Serial Number', 'Validated By Channel Finance Co', 'Validation Done On', 'Validation Time', 'Uploaded By User ID', 'Uploaded On', 'Category', 'Exception Upload'];
        const opts = { fields };

        try {
            d = new Date();
            utc = d.getTime();

            const csv = parse(newResultList, opts);
            csvfilename = "monthlyreport_" + month + "_" + year + "-" + utc + ".csv";
            csvFilePath = "/home/ubuntu/Harry/uploadedFiles/" + csvfilename;
            const fileURL = "https://sv.bluestarindia.com/uploadedFiles/" + csvfilename;

            fs.writeFile(csvFilePath, csv, (err) => {
                if (err) {
                    var returnObj = {};
                    returnObj.status = "error";
                    returnObj.message = "Error while generating report";
                    return response.status(200).send(returnObj);
                }
                returnMessage = returnMessage + " " + "Click <a href=\"" + fileURL + "\" download>here</a> to download report"
                var returnObj = {};
                returnObj.status = 'success';
                returnObj.message = returnMessage;
                return response.status(200).send(returnObj);
            });

        } catch (err) {
            var returnObj = {};
            returnObj.status = "error";
            returnObj.message = "Error while generating report";
            return response.status(200).send(returnObj);
        }
    }

    function searchSerialNumber(request, res) {
        var serialNumber = request.body.serialNumber;

        serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
            if (result != undefined && result != null) {
                var returnObj = {};
                returnObj.status = "-2";
                returnObj.message = "Serial Number already validated";
                return res.status(200).send(returnObj);
            }

            serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                if (result != undefined && result != null) {

                    var returnObj = {};
                    returnObj.status = "-2";
                    returnObj.message = "Manufactured Serial Number, Not Validated";
                    return res.status(200).send(returnObj);

                }

                serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                    if (result != undefined && result != null) {

                        var returnObj = {};
                        returnObj.status = "-2";
                        returnObj.message = "Traded Serial Number, Not Validated";
                        return res.status(200).send(returnObj);

                    }
                    var returnObj = {};
                    returnObj.status = "-1";
                    returnObj.message = "Serial Number Not Uploaded";
                    return res.status(200).send(returnObj);

                });
            });
        });
    }

    function searchSerialNumberNew(request, res) {
        var serialNumber = request.body.serialNumber;

        serialnumberdb.collection("validatedserialnumbers").findOne({ serialNumber: serialNumber }, function (err, result) {
            if (result != undefined && result != null) {
                var returnObj = {};
                returnObj.status = "-2";
                returnObj.message = "Serial Number Not Matched";
                return res.status(200).send(returnObj);
            }

            serialnumberdb.collection("manufacturingserial").findOne({ sn: serialNumber }, function (err, result) {
                if (result != undefined && result != null) {

                    var returnObj = {};
                    returnObj.status = "0";
                    returnObj.message = "Serial Number Matched";
                    return res.status(200).send(returnObj);

                }

                serialnumberdb.collection("indexedtradedserial").findOne({ serialNumber: serialNumber }, function (err, result) {
                    if (result != undefined && result != null) {

                        var returnObj = {};
                        returnObj.status = "0";
                        returnObj.message = "Serial Number Matched";
                        return res.status(200).send(returnObj);

                    }
                    var returnObj = {};
                    returnObj.status = "-1";
                    returnObj.message = "Serial Number Not Matched";
                    return res.status(200).send(returnObj);

                });
            });
        });
    }

    async function writeValidateDataIntoGoogleSheet(datatowrite, auth) {

       // Old - 1vlOgLaOFzFopGUtbfrQTXJvjKybW0hkq-ab0yWtss1o
       // New - 1pb8uT7QKhjxWPjGHfnyJwYCGQFuKQeb3X4Ni-_ZTWQQ
       //1S769asKYOsMYOahBPpKCuaRSmCFHsRAIL-uo7g_np5A
        const range = 'Validated!A2:H';

        const sheets = google.sheets({ version: 'v4', auth });
        let values = [datatowrite];
        let resource = {
            values,
        };

        await sheets.spreadsheets.values.append({
            spreadsheetId: '1S769asKYOsMYOahBPpKCuaRSmCFHsRAIL-uo7g_np5A',//old sheet - 1vlOgLaOFzFopGUtbfrQTXJvjKybW0hkq-ab0yWtss1o
            range: range,
            valueInputOption: "RAW",
            resource: resource
        }, async (err, res) => {
            console.log(err);
        });
    }

    async function writeUploadDataIntoGoogleSheet(datatowrite, auth) {
        const range = 'UploadResults!A2:J';

        const sheets = google.sheets({ version: 'v4', auth });
        let values = [datatowrite];
        let resource = {
            values,
        };

        await sheets.spreadsheets.values.append({
            spreadsheetId: '1S769asKYOsMYOahBPpKCuaRSmCFHsRAIL-uo7g_np5A',
            range: range,
            valueInputOption: "RAW",
            resource: resource
        }, async (err, res) => {
            console.log(err);
        });
    }

    async function writeValidateLogIntoGoogleSheet(datatowrite, auth) {
        const range = 'ValidateLogs!A2:E';

        const sheets = google.sheets({ version: 'v4', auth });
        let values = [datatowrite];
        let resource = {
            values,
        };

        await sheets.spreadsheets.values.append({
            spreadsheetId: '1S769asKYOsMYOahBPpKCuaRSmCFHsRAIL-uo7g_np5A',
            range: range,
            valueInputOption: "RAW",
            resource: resource
        }, async (err, res) => {
            console.log(err);
        });
    }

    async function writeSearchedLogIntoGoogleSheet(datatowrite, auth) {
        const range = 'SearchedLogs!A2:E';

        const sheets = google.sheets({ version: 'v4', auth });
        let values = [datatowrite];
        let resource = {
            values,
        };

        await sheets.spreadsheets.values.append({
            spreadsheetId: '1S769asKYOsMYOahBPpKCuaRSmCFHsRAIL-uo7g_np5A',
            range: range,
            valueInputOption: "RAW",
            resource: resource
        }, async (err, res) => {
            console.log(err);
        });
    }



    router.post('/bsl-finapi/validate', (request, response) => {

        const materialCode = request.body.materialCode;
        var serialNumber = request.body.serialNumber;
        const apiKey = request.body.apiKey;
        var uploadedDateStr = getDateStr();
        var uploadedTimeStr = getTimeStr();

        writeValidateLogIntoGoogleSheet([materialCode, serialNumber, apiKey, uploadedDateStr, uploadedTimeStr], oAuth2Client)

        if (apiKey == "pinelabs@2021" ){
            console.log("pinelab request")
            verifyApiKeyNew(request, response, oAuth2Client,0)
           }else{
            console.log("other vendor")
            verifyApiKey(request, response, oAuth2Client,0)
           }
    })

    router.post('/bsl-finapi/searchSerialNumber', (request, response) => {
        const materialCode = request.body.materialCode;
        var serialNumber = request.body.serialNumber;
        const apiKey = request.body.apiKey;
        var uploadedDateStr = getDateStr();
        var uploadedTimeStr = getTimeStr();
        writeSearchedLogIntoGoogleSheet([materialCode, serialNumber, apiKey, uploadedDateStr, uploadedTimeStr], oAuth2Client)
        verifyApiKey(request, response, oAuth2Client,1)
    })


    router.post('/bsl-finapi/searchSerial', (request, response) => {
        searchSerialNumber(request, response)
    })

    // router.post('/bsl-finapi/unblockSerialNumber', async (request, response) => {
    //     console.log("/bsl-finapi/unblockSerialNumber");
    //     const materialCode = request.body.materialCode;
    //     var serialNumber = request.body.serialNumber;
    //     const apiKey = request.body.apiKey;
    //     var unblockedDate = getDateStr();
    //     var unblockedTime = getTimeStr();
    //     var reason = request.body.reason;

    //     var keyResponse = await isValidAPIKey(apiKey, response, oAuth2Client);
    //     console.log("status = ",keyResponse);
    //     if (keyResponse.status == "success") {

    //         serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber}, function(err1, result) {
    //             if (result != undefined && result != null) {
    //                 var returnObj = {};
    //                 returnObj.responseStatus = "1";
    //                 returnObj.responseMessage = "Serial number is already unblocked before";
    //                 returnObj.responseData = result;
    //                 console.log("Response = ",returnObj);
    //                 return response.status(200).send(returnObj);
    //             } else {
    //                 serialnumberdb.collection("validatedserialnumbers").findOne({serialNumber:serialNumber}, function(err1, result) {
    //                 if (result != undefined && result != null) {
    //                     saveUnblockedSerialNumbers(serialNumber,unblockedDate,unblockedTime,apiKey,reason);
    //                     var returnObj = {};
    //                     returnObj.responseStatus = "1";
    //                     returnObj.responseMessage = "Serial number is unblocked";
    //                     returnObj.responseData = result;
    //                     console.log("Response = ",returnObj);
    //                     return response.status(200).send(returnObj);
    //                 } else {
    //                     var returnObj = {};
    //                     returnObj.responseStatus = "401";
    //                     returnObj.responseMessage = "Invalid Serial Number";
    //                     console.log("Response = ",returnObj);
    //                     return response.status(401).send(returnObj);
    //                 }
    //                 });
    //             }
    //         });            
    //     } else {
    //         var returnObj = {};
    //         returnObj.responseStatus = "403";
    //         returnObj.responseMessage = "Invalid API Key";
    //         console.log("Response = ",returnObj);
    //         return response.status(403).send(returnObj);
    //     }
    // })

    router.post('/bsl-finapi/unblockSerialNumber', async (request, response) => {
        console.log("/bsl-finapi/unblockSerialNumber");
        const materialCode = request.body.materialCode;
        var serialNumber = request.body.serialNumber;
        const apiKey = request.body.apiKey;
        var unblockedDate = getDateStr();
        var unblockedTime = getTimeStr();
        var reason = request.body.reason;
        console.log("api key",apiKey);
        console.log('Test logs');
        var keyResponse = await isValidAPIKey(apiKey, response, oAuth2Client);
        console.log("status = ",keyResponse);
        if (keyResponse.status == "success") {

            serialnumberdb.collection("unblockedserialnumber").findOne({serialNumber:serialNumber}, function(err1, result) {
                if (result != undefined && result != null) {
                    saveUnblockedSerialNumbers(serialNumber,unblockedDate,unblockedTime,apiKey,reason);
                    var returnObj = {};
                    returnObj.responseStatus = "0";
                    returnObj.responseMessage = "Serial number is unblocked";
                    //returnObj.responseData = result;
                    console.log("Response = ",returnObj);
                    return response.status(200).send(returnObj);
                } else {
                    serialnumberdb.collection("validatedserialnumbers").findOne({serialNumber:serialNumber}, function(err1, result) {
                    console.log("unblock search result",result);
                        if (result != undefined && result != null) {
                        saveUnblockedSerialNumbers(serialNumber,unblockedDate,unblockedTime,apiKey,reason);
                        var returnObj = {};
                        returnObj.responseStatus = "0";
                        returnObj.responseMessage = "Serial number is unblocked";
                        //returnObj.responseData = result;
                        console.log("Response = ",returnObj);
                        return response.status(200).send(returnObj);
                    } else {
                        var returnObj = {};
                        returnObj.responseStatus = "-1";
                        returnObj.responseMessage = "Invalid Serial Number";
                        console.log("Response = ",returnObj);
                        return response.status(401).send(returnObj);
                    }
                    });
                }
            });            
        } else {
            var returnObj = {};
            returnObj.responseStatus = "-4";
            returnObj.responseMessage = "Invalid API Key";
            console.log("Response = ",returnObj);
            return response.status(403).send(returnObj);
        }
    })

    async function isValidAPIKey(apiKey, response, auth){
        const sheets = google.sheets({ version: 'v4', auth });
        const responseData = await sheets.spreadsheets.values.get({
            spreadsheetId: '1EHkFNPCawUtKuT-ur_1M49tvtWFGoCIV8LyB1ZBPYl0',
            range: 'VendorKeys!A2:B',
        });

        if (responseData == null || responseData == undefined) {
            var returnObj = {};
            returnObj.status = "failed";
            returnObj.message = "Authentication failed";
            return returnObj;
        }

        const rows = responseData.data.values;
        var apikeyfound = false;
        var channelPartnerName = "";
        if (rows.length) {
            for (row of rows) {
                if (apiKey === row[0]) {
                    apikeyfound = true;
                    channelPartnerName = row[1];
                    break;
                }
            }
        }
         
        if (apikeyfound) {
            console.log("API key is found");
            var returnObj = {};
            returnObj.status = "success";
            returnObj.message = "API key is valid";
            returnObj.channelPartnerName = channelPartnerName;
            return returnObj;
        } else {
            var returnObj = {};
            returnObj.status = "failed";
            returnObj.message = "API key is invalid";
            return returnObj;
        }
    }

    // function saveUnblockedSerialNumbers(serialNumber, unblockedDate, unblockedTime, apiKey, reason) {
    //     console.log("saveUnblockedSerialNumbers");
    //     var timestamp = new Date().getTime();
    //     var query = { serialNumber: serialNumber, unblockedDate: unblockedDate, unblockedTime: unblockedTime, apiKey: apiKey, updatedAt: timestamp, reasonToUnblock: reason };
    //     serialnumberdb.collection("unblockedserialnumber").updateOne(
    //         {serialNumber : serialNumber},
    //         {$set:query},
    //         {upsert:true}
    //     );
    // }

    function saveUnblockedSerialNumbers(serialNumber, unblockedDate, unblockedTime, apiKey, reason) {
        console.log("saveUnblockedSerialNumbers");
        var deleteQuery = { sn: serialNumber };
        serialnumberdb.collection('blockedserialnumbers').deleteOne(deleteQuery, (err, result) => {
           console.log("query result",result);
            if (err) {
                console.log("Error = ",err)
            } else {
                var timestamp = new Date().getTime();
                var query = { serialNumber: serialNumber, unblockedDate: unblockedDate, unblockedTime: unblockedTime, apiKey: apiKey, updatedAt: timestamp, reasonToUnblock: reason };
                serialnumberdb.collection("unblockedserialnumber").updateOne(
                    {serialNumber : serialNumber},
                    {$set:query},
                    {upsert:true}
                );
            }
        });
    }
    
    router.post('/bsl-finapi/createCFC', async (request, response) => {
        var mobileNumber = request.body.mobileNumber;
        const apiKey = request.headers.authorization;
        console.log("Authorization = ",request.headers.authorization)
        console.log("header = ",request.headers)

        if (mobileNumber == null || mobileNumber == undefined) {
            var returnObj = {}
            returnObj.status = "failed"
            returnObj.message = "MobileNumber is missing."
            return response.status(406).send(returnObj)
        }

        var keyResponse = await isValidAPIKey(apiKey, response, oAuth2Client);
        console.log("status = ",keyResponse);
        if (keyResponse.status == "failed") {
            return response.status(404).send(keyResponse)
        } else {

            var date = new Date();
            var dateNow = date.getTime();

            date.setHours(date.getHours() - 1)
            var hourBeforTime = date.getTime();
            console.log("HourBeforeTime = ",hourBeforTime)
            console.log("dateNow = ",dateNow)

            serialnumberdb.collection("CFCNumber").find({"createdAt":{$lte:dateNow,$gt:hourBeforTime},"mobileNumber":mobileNumber}).sort({createdAt:-1}).toArray(function(err5, result5){
                var returnObj = {};
                console.log("result5 = ",result5)
                if (result5.length > 0) {

                    var record = result5[0]
                    serialnumberdb.collection("SerialNumberWithCFC").
                    find({"cfcNumber":record.cfcNumber,"apiKey":apiKey}).
                    toArray(function(err6, result6){
                        if (result6.length > 1) {
                            var start = new Date();
                            start.setUTCHours(0,0,0,0);
                            var timestamp = start.getTime()

                            serialnumberdb.collection("CFCNumber").find({"createdAt":{$gt:timestamp},"mobileNumber":mobileNumber}).sort({createdAt:-1}).toArray(function(err4,result4){
                                console.log("Result4 = ",result4)
                                if (result4.length > 1) {
                                    var returnObj = {}
                                    returnObj.status = "failed"
                                    returnObj.message = "CFC generation limit exceeded."
                                    return response.status(406).send(returnObj)
                                } else {
                                    var cfc = generateString(1)+'-'+generateNumber(6)
                                    console.log('CFC created = ',cfc)

                                    serialnumberdb.collection("CFCNumber").find({"cfcNumber":cfc,"mobileNumber":mobileNumber}).sort({createdAt:-1}).toArray(function (err, result1) {
                                        var returnObj = {};
                                        console.log("Result1 = ",result1)
                                        if (result1.length > 0) {
                                            returnObj.status = "failed"
                                            returnObj.message = "Failed to generate CFC number. Please try again."
                                            return response.status(403).send(returnObj)
                                        } else {
                                            returnObj.result = 'success'
                                            returnObj.message = 'CFC is created successfully'
                                            returnObj.createdAt = dateNow
                                            returnObj.cfc = cfc
                                            returnObj.mobileNumber = mobileNumber
                                            returnObj.channelPartnerName = keyResponse.channelPartnerName
                                            returnObj.apiKey = apiKey
    
                                            var query = {createdAt:returnObj.createdAt , cfcNumber:cfc, mobileNumber: mobileNumber, status:'pending', channelPartnerName:keyResponse.channelPartnerName,apiKey:apiKey}
                                            serialnumberdb.collection('CFCNumber').insertOne(query, (err, result) => {
                                                if (err) {
                                                    console.log('Error while inserting CFCNumber ', err)
                                                    returnObj.status = "failed"
                                                    returnObj.message = "Failed to generate CFC number. Please try again."        
                                                    return response.status(403).send(returnObj);
                                                } else {
                                                    console.log('CFCNumber inserted ')
                                                    var smsContent = "Dear Customer, Your Consumer Finance Code is "+returnObj.cfc+". Thank You, Blue Star Ltd."
                                                    var smsObj = {
                                                        msg: smsContent,
                                                        send_to: returnObj.mobileNumber,
                                                        userid: "000-000-133-86732",
                                                        password: "OJT4wp6~#V"
                                                    }
                                                    const fetchURL = "https://sv.bluestarindia.com:2020/GatewayAPI/restWithoutSignature";
                                                    axios.post(fetchURL, smsObj)
                                                        .then(function (response) {
                                                            //console.log(response);
                                                        })
                                                        .catch(function (error) {
                                                            console.log(error);
                                                        });
                                                    
                                                    return response.status(200).send(returnObj);
                                                }
                                            });
                                        }
                                    })
                                }
                            });
                        } else {
                            returnObj.result = 'success'
                            returnObj.message = 'CFC is available.'
                            returnObj.createdAt = record.createdAt
                            returnObj.cfc = record.cfcNumber
                            returnObj.mobileNumber = record.mobileNumber
                            returnObj.channelPartnerName = record.channelPartnerName
                            returnObj.apiKey = record.apiKey

                            var smsContent = "Dear Customer, Your Consumer Finance Code is "+returnObj.cfc+". Thank You, Blue Star Ltd."
                            var smsObj = {
                                msg: smsContent,
                                send_to: returnObj.mobileNumber,
                                userid: "000-000-133-86732",
                                password: "OJT4wp6~#V"
                            }
                            const fetchURL = "https://sv.bluestarindia.com:2020/GatewayAPI/restWithoutSignature";
                        
                            axios.post(fetchURL, smsObj)
                              .then(function (response) {
                                //console.log(response);
                              })
                              .catch(function (error) {
                                console.log(error);
                              });
                            return response.status(200).send(returnObj);
                        }
                    })
                } else {

                    var start = new Date();
                    start.setUTCHours(0,0,0,0);
                    var timestamp = start.getTime()
            
                    serialnumberdb.collection("CFCNumber").find({"createdAt":{$gt:timestamp},"mobileNumber":mobileNumber}).sort({createdAt:-1}).toArray(function(err4,result4){
                        console.log("Result4 = ",result4)
                        if (result4.length > 1) {
                            var returnObj = {}
                            returnObj.status = "failed"
                            returnObj.message = "CFC generation limit exceeded."
                            return response.status(406).send(returnObj)
                        } else {
                            var cfc = generateString(1)+'-'+generateNumber(6)
                            console.log('CFC created = ',cfc)

                            serialnumberdb.collection("CFCNumber").find({"cfcNumber":cfc,"mobileNumber":mobileNumber}).sort({createdAt:-1}).toArray(function (err, result1) {
                                var returnObj = {};
                                console.log("Result1 = ",result1)
                                if (result1.length > 0) {
                                    returnObj.status = "failed"
                                    returnObj.message = "Failed to generate CFC number. Please try again."
                                    return response.status(403).send(returnObj)
                                } else {
                                    returnObj.result = 'success'
                                    returnObj.message = 'CFC is created successfully'
                                    returnObj.createdAt = dateNow
                                    returnObj.cfc = cfc
                                    returnObj.mobileNumber = mobileNumber
                                    returnObj.channelPartnerName = keyResponse.channelPartnerName
                                    returnObj.apiKey = apiKey
    
                                    var query = {createdAt:returnObj.createdAt , cfcNumber:cfc, mobileNumber: mobileNumber, status:'pending', channelPartnerName:keyResponse.channelPartnerName,apiKey:apiKey}
                                    serialnumberdb.collection('CFCNumber').insertOne(query, (err, result) => {
                                        if (err) {
                                            console.log('Error while inserting CFCNumber ', err)
                                            returnObj.status = "failed"
                                            returnObj.message = "Failed to generate CFC number. Please try again."        
                                            return response.status(403).send(returnObj);
                                        } else {
                                            console.log('CFCNumber inserted ')
                                            var smsContent = "Dear Customer, Your Consumer Finance Code is "+returnObj.cfc+". Thank You, Blue Star Ltd."
                                            var smsObj = {
                                                msg: smsContent,
                                                send_to: returnObj.mobileNumber,
                                                userid: "000-000-133-86732",
                                                password: "OJT4wp6~#V"
                                            }
                                            const fetchURL = "https://sv.bluestarindia.com:2020/GatewayAPI/restWithoutSignature";
                                            axios.post(fetchURL, smsObj)
                                                .then(function (response) {
                                                    //console.log(response);
                                                })
                                                .catch(function (error) {
                                                    console.log(error);
                                                });
                                            
                                            return response.status(200).send(returnObj);
                                        }
                                    });
                                }
                            })
                        }
                    });
                }
            })
        }
    })

    async function cfcUsedFor(cfcNumber,apiKey) {
        serialnumberdb.collection("SerialNumberWithCFC").find({"cfcNumber":cfcNumber,"apiKey":apiKey}).toArray(function (err3, result3) {
            return result3
        })
    }

    router.post('/bsl-finapi/verifyCFC', async (request, response) => {

        const modelCode = request.body.modelCode;
        var cfcNumber = request.body.cfcNumber;
        var uploadedDateStr = getDateStr();
        var uploadedTimeStr = getTimeStr();
        var apiKey = request.body.apiKey;

        var keyResponse = await isValidAPIKey(apiKey, response, oAuth2Client);
        if (keyResponse.status == "failed") {
            return response.status(404).send(keyResponse)
        } else {
            console.log("Checking CFCNumber")
            // serialnumberdb.collection("CFCNumber").find({"cfcNumber":cfcNumber}).sort({createdAt:-1}).toArray(function (err, result) {
                // serialnumberdb.collection("CFCNumber").findOne({"cfcNumber":cfcNumber}, function (err, result) {
            serialnumberdb.collection("CFCNumber").find({"cfcNumber":cfcNumber}).sort({createdAt:-1}).toArray(function (err, result) {
                if (result == undefined || result == null || result.length == 0) {
                    var returnObj = {};
                    returnObj.status = "failed"
                    returnObj.message = "CFC not found."
                    return response.status(403).send(returnObj)
                } else {
                    console.log("Checking CFC validity")
                    var record = result[0]
                    var date = new Date()
                    var currentTime = date.getTime()
                    var recordTime = record.createdAt;
                    var timeDiffrence = currentTime - recordTime
                    if (timeDiffrence > (60*60*1000)) {
                        var returnObj = {};
                        returnObj.status = "failed"
                        returnObj.message = "CFC validity is expired."
                        console.log(returnObj)
                        return response.status(403).send(returnObj)        
                    } else {
                        console.log("Checking CFC verification")

                        serialnumberdb.collection("SerialNumberWithCFC").find({"cfcNumber":cfcNumber,"apiKey":apiKey}).toArray(function (err3, result3) {
                            if (result3.length > 1) {
                                var returnObj = {};
                                returnObj.status = "failed"
                                returnObj.message = "CFC verification limit exceeded."
                                return response.status(403).send(returnObj)  
                            } else {
                                console.log("Checking manufacturing")
                                serialnumberdb.collection("manufacturingserial").findOne({ mc: modelCode }, function (err4, result4) {
                                    if (result4 != undefined && result4 != null) {
                
                                        serialnumberdb.collection("CFCNumber").updateOne({_id:result._id},{$set:{status:"verified"}},(err1, result1)=>{
                                            if (result1 == null || result1 == undefined) {
                                                var returnObj = {};
                                                returnObj.status = "failed"
                                                returnObj.message = "Unknown error."
                                                return response.status(500).send(returnObj)
                                            } else {
                                                var query = { modelCode: modelCode, cfcNumber:cfcNumber,mobileNumber:result.mobileNumber,createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:keyResponse.channelPartnerName,apiKey:apiKey};
                                                serialnumberdb.collection('SerialNumberWithCFC').insertOne(query, (err2, result2) => {
                                                    var returnObj = {};
                                                    returnObj.status = "success"
                                                    returnObj.message = "CFC verified."
                                                    return response.status(200).send(returnObj)
                                                });
                                                // serialnumberdb.collection("SerialNumberWithCFC").updateOne({cfcNumber:cfcNumber,modelCode:modelCode},{$set:query},{upsert:true},(err2,result2)=>{ 
                                                // })
                                            }
                                        })
                                    } else {
                                        console.log("Checking indextradedserial")
                                        serialnumberdb.collection("indexedtradedserial").findOne({ mCode: modelCode }, function (err5, result5) {
                                            if (result5 != undefined && result5 != null) {
                
                                                serialnumberdb.collection("CFCNumber").updateOne({_id:result._id,"apiKey":apiKey},{$set:{status:"verified"}},(err1, result1)=>{
                                                    if (result1 == null || result1 == undefined) {
                                                        var returnObj = {};
                                                        returnObj.status = "failed"
                                                        returnObj.message = "Unknown error."
                                                        return response.status(500).send(returnObj)
                                                    } else {
                                                        var query = { modelCode: modelCode, cfcNumber:cfcNumber,mobileNumber:result.mobileNumber,createdAt:Date.now(),updatedAt:Date.now(), channelPartnerName:keyResponse.channelPartnerName,apiKey:apiKey};
                                                        serialnumberdb.collection('SerialNumberWithCFC').insertOne(query, (err2, result2) => {
                                                            var returnObj = {};
                                                            returnObj.status = "success"
                                                            returnObj.message = "CFC verified."
                                                            return response.status(200).send(returnObj)
                                                        });
                                                        // serialnumberdb.collection("SerialNumberWithCFC").updateOne({cfcNumber:cfcNumber,modelCode:modelCode},{$set:query},{upsert:true},(err2,result2)=>{
                                                        //     var returnObj = {};
                                                        //     returnObj.status = "success"
                                                        //     returnObj.message = "CFC verified."
                                                        //     return response.status(200).send(returnObj)
                                                        // })
                                                    }
                                                })
                                            } else {
                                                var returnObj = {};
                                                returnObj.status = "failed"
                                                returnObj.message = "Model code not found."
                                                return response.status(200).send(returnObj)
                                            }
                                        });
                                    }
                                });
                            }
                        })
                    }
                 }
            })
        }
    })

    function pad(num, size) {
        var s = num + "";
        while (s.length < size) s = "0" + s;
        return s;
    }

    function sendEmailWithAttachment(userId, fileName) {
        let transport = nodemailer.createTransport({
            host: 'smtp.sendgrid.com',
            port: 587,
            pool: true,
            auth: {
                user: 'connect@bluestarindia.com',
                pass: 'P@ssw0rd'
            },
            tls: {
                rejectUnauthorized: false
            }
        });

        const emailId = userId + "@bluestarindia.com"
        const filePath = "/home/ubuntu/Harry/uploadedFiles/" + fileName;

        const message = {
            from: 'connect@bluestarindia.com', // Sender address
            to: emailId,         // List of recipients
            subject: "Serial Number Upload Details", // Subject line
            text: "Hello,\n\nPlease find enclosed here with the details of file upload along with remarks.\n\nBest Regards,\nIT Team\n\n", // Plain text body
            attachments: [{ filename: fileName, path: filePath }]
        };

        transport.sendMail(message, function (err, info) {
            if (err) {
                console.log("Error");
                console.log(err);
            } else {
                console.log("Success");
                console.log(info);
            }
        });
    }

    router.get('/uploadedFiles/:fileName', (req, res) => {
        var files = fs.createReadStream("./uploadedFiles/" + req.params.fileName);
        res.writeHead(200, { 'Content-disposition': 'attachment; filename=' + req.params.fileName }); //here you can add more headers
        files.pipe(res)
    })

    router.get('/lastupdatedon', (req, res) => {
        fs.readFile('/home/ubuntu/Harry/lastupdatedon.txt', 'utf8', (err, data) => {
            var returnObj = {};
            returnObj.lastupdatedon = data;
            return res.status(200).send(returnObj);
        });

    })

    function generateNumber(length) {
        var add = 1, max = 12 - add;   // 12 is the min safe number Math.random() can generate without it starting to pad the end with zeros.   

        if ( length > max ) {
                return generate(max) + generate(n - max);
        }

        max        = Math.pow(10, length+add);
        var min    = max/10; // Math.pow(10, n) basically
        var number = Math.floor( Math.random() * (max - min + 1) ) + min;

        return ("" + number).substring(add); 
    }

    function generateString(length) {
        var result           = '';
        var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        var charactersLength = characters.length;
        for ( var i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() * 
            charactersLength));
        }
        return result;
    }

    router.get('/readExcel', (req, res) => {
        console.log('Read Excel')
        const file = xlsxreader.readFile('./tempfiles/BlockingList.xlsx')
  
        let data = []
  
        const sheets = file.SheetNames
        console.log('Shee count ',sheets.length)

        var serialNumber = []
  
        for(let i = 0; i < sheets.length; i++)
        {
            const temp = xlsxreader.utils.sheet_to_json(
            file.Sheets[file.SheetNames[i]])
            temp.forEach((res) => {
                var dictionary = {}
                dictionary.product_family_name = res["Product Family Name"]
                dictionary.product_sub_family_name = res["Product Sub Family Name"]
                dictionary.model = res["Model"]
                dictionary.serial_number = res["Product Serial No."]
                serialNumber.push(dictionary.serial_number)
                data.push(dictionary)
            })
        }
  

        // Printing data
        console.log("Total Serial numbers are ",serialNumber.length)

        var query1 = { sn: { $in: serialNumber } };
        serialnumberdb.collection("manufacturingserial").find(query1).toArray(function (err, result) {
            // console.log(serialNumber)
            var manufacturingNumbers = result.map(function(obj) {
                return obj.sn;
            });
            console.log('manufacturingserial Result count',manufacturingNumbers.length)

            var query2 = { serialNumber: { $in: serialNumber } };
            serialnumberdb.collection("indexedtradedserial").find(query2).toArray(function (err1, result1) {
                // console.log(serialNumber)
                var indexedNumbers = result1.map(function(obj) {
                    return obj.serialNumber;
                });
                console.log('indexedtradedserial Result count',indexedNumbers.length)
                // return res.status(200).send(result1);

                var validNumbers = manufacturingNumbers.concat(indexedNumbers)
                // var validNumberSet = new Set(validNumbers);
                var validNumberSet = validNumbers.filter(function(item, pos) {
                                    return validNumbers.indexOf(item) == pos;
                                    })

                console.log('valid numbers count',validNumberSet.length)
                var query3 = {sn:{ $in: validNumberSet} }
                serialnumberdb.collection("blockedserialnumbers").find(query3).toArray(function (err2, result2) {
                    // console.log(serialNumber)
                    var blockedNumbers = result2.map(function(obj) {
                        return obj.sn;
                    });

                    var validNumberSet1 = validNumberSet.filter( function(snumber) {
                        return !blockedNumbers.includes(snumber);
                    });

                    console.log('blockedserialnumbers Result count',blockedNumbers.length)
                    console.log('After removing Blocked Result count',validNumberSet1.length)

                    // return res.status(200).send(result2);
                    var query4 = { serialNumber: { $in: validNumberSet1 } };
                    serialnumberdb.collection("validatedserialnumbers").find(query4).toArray(function (err3, result3) {
                        // console.log(result3)
                        var validatedNumbers = result3.map(function(obj) {
                            return obj.serialNumber;
                        });

                        var validNumberSet2 = validNumberSet1.filter( function(snumber) {
                        // return those elements not in the namesToDeleteSet
                            return !validatedNumbers.includes(snumber);
                        });

                        console.log('validatedserialnumbers Result count',validatedNumbers.length)
                        console.log('validNumbers Result count',validNumberSet2.length)

                        var payload = []
                        for (var i = 0; i < validNumberSet2.length; i++) {
                            // var objectId = new ObjectID()
                            var dictionary = {sn:validNumberSet2[i]}
                            payload.push(dictionary)
                        }

                        console.log("payload = ",payload.length)
                        // return res.status(200).send(payload);

                        serialnumberdb.collection('blockedserialnumbers').insertMany(payload, (err, result) => {
                            if (err) {
                                console.log("Error = ",err)
                            } else {
                                console.log(result.length)
                                return res.status(200).send(payload);
                            }
                        });
                        
                    })
                })
            })
        })
    })

    app.use('/', router)

    MongoClient.connect('mongodb://127.0.0.1:27017', { useNewUrlParser: true, useUnifiedTopology: true }, (err, client) => {
        if (err) {
            return console.log(err);
        } else {
            serialnumberdb = client.db('mukeshdb');
            startrackdb = client.db('startrackdb');
            https.createServer(optionshttps, app).listen(PORT);
            console.log("Server is listening on port ", PORT);
        }
    });

}
