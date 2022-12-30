Dropzone.autoDiscover = false

// https://stackoverflow.com/questions/3665115/how-to-create-a-file-in-memory-for-user-to-download-but-not-through-server

function downloadBinary(blob, name) {
	let a = document.createElement("a")
	a.style = "display: none"
	a.download = name

	let url = URL.createObjectURL(blob)
	a.href = url

	document.body.appendChild(a)
	a.click()
	URL.revokeObjectURL(url)
}

function downloadUrl(url) {
	let a = document.createElement("a")
	a.setAttribute("href", url)

	document.body.appendChild(a)
	a.click()
	document.body.removeChild(a)
}
