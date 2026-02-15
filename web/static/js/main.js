document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('apk-file');
    const form = document.getElementById('upload-form');
    const progressBar = document.querySelector('.progress-wrapper');
    const statusText = document.querySelector('.status-text');

    // Drag & Drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');

        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    dropZone.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            handleFileSelect(fileInput.files[0]);
        }
    });

    function handleFileSelect(file) {
        document.querySelector('.drop-zone h2').textContent = file.name;
        document.querySelector('.drop-zone p').textContent = "Ready to Scan";

        // Auto submit or show button? 
        // Let's auto-submit for seamless feel, or show a button.
        // Better: Show progress bar and submit.

        progressBar.style.display = 'block';
        statusText.textContent = "INITIALIZING SCANNER...";

        // Simulate progress then submit
        let width = 0;
        const interval = setInterval(() => {
            width += 5;
            document.querySelector('.progress-bar').style.width = width + '%';
            if (width >= 100) {
                clearInterval(interval);
                statusText.textContent = "UPLOADING & ANALYZING...";
                form.submit();
            }
        }, 50);
    }
});
