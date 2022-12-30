const myDropzone = new Dropzone("div#dropzoned", {
	paramName: "file",
	acceptedFiles: ".png,.jpg,.jpeg",

	accept: function (file, done) {
		if (document.getElementById("password").value == "") {
			done("Invalid password")
		}
		done()
	},

	// Called just before the file is sent.
	sending(_file, xhr, form) {
		form.append("password", password.value)
		xhr.responseType = "arraybuffer"
	},

	// When the complete upload is finished and successful
	success(file) {
		let blob = new Blob([file.xhr.response])
		let header = file.xhr.getResponseHeader("Content-Disposition")
		let name = header.split("filename=")[1]
		downloadBinary(blob, name)

		if (file.previewElement) {
			return file.previewElement.classList.add("dz-success")
		}
	},

	// Called whenever an error occurs
	// Receives `file` and `message`
	error(file, message) {
		if (file.previewElement) {
			file.previewElement.classList.add("dz-error")
			if (typeof message !== "string" && message.error) {
				message = message.error
			}
			if (file.xhr?.response) {
				let enc = new TextDecoder("utf-8")
				message = enc.decode(file.xhr.response)
			}
			for (let node of file.previewElement.querySelectorAll("[data-dz-errormessage]")) {
				node.textContent = message
			}
		}
	},
})
