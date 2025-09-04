// Test the verification email endpoint
const testData = {
  email: "test@example.com",
  firstName: "John",
  lastName: "Doe", 
  password: "password123",
  userData: {
    phone: "+1234567890",
    acceptMarketing: false,
    role: "user"
  }
};

console.log("Test data:", JSON.stringify(testData, null, 2));

// Test the endpoint
fetch('https://kise-api-service1.onrender.com/api/send-verification-email', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(testData)
})
.then(response => {
  console.log("Response status:", response.status);
  return response.text();
})
.then(text => {
  console.log("Response text:", text);
  try {
    const json = JSON.parse(text);
    console.log("Response JSON:", json);
  } catch (e) {
    console.log("Not valid JSON");
  }
})
.catch(error => {
  console.error("Error:", error);
});
