import qrcode

URL = "https://animal-detection-backend-vdbb.onrender.com"

img = qrcode.make(URL)
img.save("animal_detection_global_qr.png")

print("QR generated successfully")
