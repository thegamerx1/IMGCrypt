let dataInput = document.getElementById("dataInput")
let isFileUpload = document.getElementById("isFileUpload")
let fileInput = document.getElementById("fileInput")
let select = document.getElementById("selecttype")

select.addEventListener("change", () => {
	if (select.value == "file") {
		dataBox.classList.add("d-none")
		fileBox.classList.remove("d-none")
	} else {
		dataBox.classList.remove("d-none")
		fileBox.classList.add("d-none")
	}
})

const myDropzone = new Dropzone("div#dropzoned", {
	paramName: "file",
	acceptedFiles: ".png,.jpg,.jpeg",
	accept: function (file, done) {
		console.log("aaaaaa")
		if (select.value == "file") {
			let file = fileInput.files[0]
			if (!file) {
				done("No input file!")
			}
		} else {
			let data = dataInput.value
			if (data === "") {
				done("Empty data value!")
			}
		}
		if (password.value == "") {
			done("Invalid password")
		}
		done()
	},

	// Called just before the file is sent.
	sending(_file, _xhr, form) {
		let file =
			select.value == "file"
				? fileInput.files[0]
				: new Blob([dataInput.value], { type: "text/plain" })
		form.append("data", file, select.value == "file" ? file.name : "text.txt")
		form.append("password", password.value)
	},

	// When the complete upload is finished and successful
	success(file) {
		downloadUrl(`/download/${file.xhr.responseText}`)

		if (file.previewElement) {
			return file.previewElement.classList.add("dz-success")
		}
	},
})
