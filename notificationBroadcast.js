/**
 ## WARNING ##
 If you want to make any changes in this file
 please make sure to generate sha256 hash and include in html file where this file is used.
 ## ------- ##
 */

function getURLParameter(p) {
    const sPageURL = window.location.search.substring(1);
    const sURLVariables = sPageURL.split('&');
    for (let i = 0; i < sURLVariables.length; i++) {
        let sParameterName = sURLVariables[i].split('=');
        if (sParameterName[0] == p) {
            return sParameterName[1].replace(/%20/g, ' ');
        }
    }
    return "";
}

window.onload = function () {
    captureSession();

    document.getElementById('topMenu').addEventListener('change', onTopMenuSelection);
    document.getElementById('topicType').addEventListener('change', onTopicTypeSelection);
    document.getElementById('yearType').addEventListener('change', onYearTypeSelection);
    document.getElementById('monthType').addEventListener('change', onMonthTypeSelection);
    document.getElementById('uploadBtn').addEventListener('click', uploadSerialNumberConfirmation);
    document.getElementById('searchBtn').addEventListener('click', searchSerialNumber);
    document.getElementById('reportBtn').addEventListener('click', reportSerialNumber);
}

function triggerDatePicker(e) {
    //$("#datepicker").datepicker( "show" );
}

function captureSession() {
    this.sessionID = getURLParameter('session')
    document.getElementById('username').innerHTML = 'Welcome ' + getURLParameter('username')
    document.getElementById('lastloadtext').innerHTML = 'Last updated on'

    document.getElementById('userInfo').style.display = 'block'
    document.getElementById('lastloadstatus').style.display = 'block'

    getLastUpdatedOnDate()

}

function onTopicTypeSelection() {
    topicSelected();
    const selectedTopicType = document.getElementById('topicType').value
    const uploadFileComponent = document.getElementById('uploadFileComponent')
    const uploadFileComponent1 = document.getElementById('uploadFileComponent1')

    const materialCodeComponent = document.getElementById('materialCodeComponent')
    const fromSerialComponent = document.getElementById('fromSerialComponent')
    const toSerialComponent = document.getElementById('toSerialComponent')
    const singleSerialComponent = document.getElementById('singleSerialComponent')
    const successMessageComponent = document.getElementById('successMessageComponent')


    if (selectedTopicType == 'csvupload') {
        uploadFileComponent.style = 'display: block;'
        uploadFileComponent1.style = 'display: block;'
        materialCodeComponent.style = 'display: none;'
        fromSerialComponent.style = 'display: none;'
        toSerialComponent.style = 'display: none;'
        singleSerialComponent.style = 'display: none;'
        successMessageComponent.style = 'display: none;'

    } else if (selectedTopicType == 'rangeupload') {
        uploadFileComponent.style = 'display: none;'
        uploadFileComponent1.style = 'display: none;'

        materialCodeComponent.style = 'display: block;'
        fromSerialComponent.style = 'display: block;'
        toSerialComponent.style = 'display: block;'
        singleSerialComponent.style = 'display: none;'
        successMessageComponent.style = 'display: none;'

    } else if (selectedTopicType == 'singleupload') {
        uploadFileComponent.style = 'display: none;'
        uploadFileComponent1.style = 'display: none;'

        materialCodeComponent.style = 'display: block;'
        fromSerialComponent.style = 'display: none;'
        toSerialComponent.style = 'display: none;'
        singleSerialComponent.style = 'display: block;'
        successMessageComponent.style = 'display: none;'

    }
}

function onYearTypeSelection() {

}

function onMonthTypeSelection() {

}


function onTopMenuSelection() {
    topicSelected();

    const selectedMenu = document.getElementById('topMenu').value
    const uploadTypeComponent = document.getElementById('uploadTypeComponent')
    const uploadFileComponent = document.getElementById('uploadFileComponent')
    const uploadFileComponent1 = document.getElementById('uploadFileComponent1')
    const reportTypeComponent = document.getElementById('reportTypeComponent')

    const materialCodeComponent = document.getElementById('materialCodeComponent')
    const fromSerialComponent = document.getElementById('fromSerialComponent')
    const toSerialComponent = document.getElementById('toSerialComponent')
    const singleSerialComponent = document.getElementById('singleSerialComponent')
    const successMessageComponent = document.getElementById('successMessageComponent')
    const uploadButtonComponent = document.getElementById('uploadButtonComponent')
    const searchButtonComponent = document.getElementById('searchButtonComponent')
    const reportButtonComponent = document.getElementById('reportButtonComponent')

    const remarksComponent = document.getElementById('remarksComponent')

    if (selectedMenu == 'upload') {
        uploadTypeComponent.style = 'display: block;'
        uploadFileComponent.style = 'display: block;'
        uploadFileComponent1.style = 'display: block;'
        materialCodeComponent.style = 'display: none;'
        fromSerialComponent.style = 'display: none;'
        toSerialComponent.style = 'display: none;'
        singleSerialComponent.style = 'display: none;'
        successMessageComponent.style = 'display: none;'
        uploadButtonComponent.style = 'display: block;'
        searchButtonComponent.style = 'display: none;'
        remarksComponent.style = 'display: block;'
        reportTypeComponent.style = 'display: none;'
        reportButtonComponent.style = 'display: none;'


    } else if (selectedMenu == 'search') {
        uploadTypeComponent.style = 'display: none;'
        uploadFileComponent.style = 'display: none;'
        uploadFileComponent1.style = 'display: none;'
        materialCodeComponent.style = 'display: none;'
        fromSerialComponent.style = 'display: none;'
        toSerialComponent.style = 'display: none;'
        singleSerialComponent.style = 'display: block;'
        successMessageComponent.style = 'display: none;'
        uploadButtonComponent.style = 'display: none;'
        searchButtonComponent.style = 'display: block;'
        remarksComponent.style = 'display: none;'
        reportTypeComponent.style = 'display: none;'
        reportButtonComponent.style = 'display: none;'

    } else if (selectedMenu == 'report') {
        uploadTypeComponent.style = 'display: none;'
        uploadFileComponent.style = 'display: none;'
        uploadFileComponent1.style = 'display: none;'
        materialCodeComponent.style = 'display: none;'
        fromSerialComponent.style = 'display: none;'
        toSerialComponent.style = 'display: none;'
        singleSerialComponent.style = 'display: none;'
        successMessageComponent.style = 'display: none;'
        uploadButtonComponent.style = 'display: none;'
        searchButtonComponent.style = 'display: none;'
        remarksComponent.style = 'display: none;'
        reportTypeComponent.style = 'display: block;'
        reportButtonComponent.style = 'display: block;'
    }
}

function clearFormElements() {
}

function topicSelected() {
}

function uploadSerialNumberConfirmation() {
    const r = confirm("Do you really want to upload?");
    if (r == true) {
        var spinner = new jQuerySpinner({
            parentId: 'supercontainer'
        });
        spinner.show()


        var successMessageComponent = document.getElementById('successMessageComponent')
        successMessageComponent.style = 'display: block;'

        const selectedTopicType = document.getElementById('topicType').value
        if (selectedTopicType == 'csvupload') {
            uploadSerialNumber(spinner)
        } else if (selectedTopicType == 'rangeupload') {
            rangeUpload(spinner)
        } else if (selectedTopicType == 'singleupload') {
            singleUpload(spinner)
        }
    }
}

function searchSerialNumber() {
    const spinner = new jQuerySpinner({
        parentId: 'supercontainer'
    });
    spinner.show()

    const successMessageComponent = document.getElementById('successMessageComponent');
    successMessageComponent.style = 'display: block;'

    searchSerial(spinner)
}

function reportSerialNumber() {
    const spinner = new jQuerySpinner({
        parentId: 'supercontainer'
    });
    spinner.show()

    const successMessageComponent = document.getElementById('successMessageComponent');
    successMessageComponent.style = 'display: block;'

    generateReport(spinner)
}

function generateReport(spinner) {
    const yearVal = document.getElementById('yearType').value
    const monthVal = document.getElementById('monthType').value

    const requestBody = {
        "month": monthVal,
        "year": yearVal
    }
    fetch("/generateReport",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Accept': 'application/json',
                'session': this.sessionID
            },
            body: JSON.stringify(requestBody)
        }).then(response => {
        return response.json()
    }).then(output => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = '<p>' + output.message + '</p><br><p>' + output.status + '</p>'
        clearFormElements()
    }).catch(error => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = error
    })
}

function rangeUpload(spinner) {
    const mCode = document.getElementById('materialCode').value
    const fromSerialNumber = document.getElementById('fromSerial').value
    const toSerialNumber = document.getElementById('toSerial').value
    const remarks = document.getElementById('remarks').value


    const requestBody = {
        "mCode": mCode,
        "fromSerialNumber": fromSerialNumber,
        "toSerialNumber": toSerialNumber,
        "remarks": remarks
    }
    fetch("/rangeSerialUpload",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Accept': 'application/json',
                'session': this.sessionID
            },
            body: JSON.stringify(requestBody)
        }).then(response => {
        return response.json()
    }).then(output => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = output.status
        clearFormElements()
    }).catch(error => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = error
    })
}

function singleUpload(spinner) {
    const mCode = document.getElementById('materialCode').value
    const serialNumber = document.getElementById('singleSerial').value
    const remarks = document.getElementById('remarks').value

    const requestBody = {
        "mCode": mCode,
        "serialNumber": serialNumber,
        "remarks": remarks
    }
    fetch("/singleSerialUpload",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Accept': 'application/json',
                'session': this.sessionID
            },
            body: JSON.stringify(requestBody)
        }).then(response => {
        return response.json()
    }).then(output => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = output.status
        clearFormElements()
    }).catch(error => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = error
    })
}

function searchSerial(spinner) {
    const serialNumber = document.getElementById('singleSerial').value

    const requestBody = {
        "serialNumber": serialNumber
    }

    fetch("/bsl-finapi/searchSerial",
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Accept': 'application/json',
                'session': this.sessionID
            },
            body: JSON.stringify(requestBody)
        }).then(response => {
        return response.json()
    }).then(output => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = output.message
        clearFormElements()
    }).catch(error => {
        spinner.hide()
        document.getElementById("success_message").innerHTML = error
    })
}

function uploadSerialNumber(spinner) {

    document.getElementById("success_message").innerHTML = 'Uploading Serial Numbers...'
    const remarks = document.getElementById('remarks').value
    const files = document.getElementById("imageURL").files;
    const formData = new FormData();
    formData.append('myFile', files[0]);
    const uploadurl = "/upload?remarks=" + btoa(remarks);
    fetch(uploadurl, {
        method: 'POST',
        body: formData,
        headers: {
            'session': this.sessionID
        }
    })
        .then(response => {
            return response.json()
        })
        .then(data => {
            spinner.hide()
            document.getElementById("success_message").innerHTML = data.status
        })
        .catch(error => {
            spinner.hide()
            document.getElementById("success_message").innerHTML = error
        })
}

function getLastUpdatedOnDate() {
    fetch("/lastupdatedon",
        {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Accept': 'application/json',
                'session': this.sessionID
            }
        }).then(response => {
        return response.json()
    }).then(output => {
        document.getElementById("lastloadtext").innerHTML = "Last updated on " + output.lastupdatedon
        clearFormElements()
    }).catch(error => {
        document.getElementById("lastloadtext").innerHTML = "Last updated on"
    })
}
