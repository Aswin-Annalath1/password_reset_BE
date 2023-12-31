const nodemailer = require("nodemailer");

exports.sendEmail = async (email, subject, payload) => { //Details got from auth controller..
  try {
//It configures the Nodemailer transport using the provided email and authentication credentials 
    const transporter = nodemailer.createTransport({
      service: process.env.SERVICE,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
    });
//It defines the email options, including the sender address,recipient address,email subject and the HTML content of the email.
    const mailOptions = {
      from: process.env.USER,
      to: email,  //Details got from auth controller
      subject: subject, 
      html: `<!doctype html>
      <html lang="en-US">
          <head>
              <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
              <title>Reset Password Email Template</title>
              <meta name="description" content="Reset Password Email Template.">
              <style type="text/css">
                  a:hover {text-decoration: underline !important;}
              </style>
          </head>
          <body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
              <!--100% body table-->
              <table cellspacing="0" border="0" cellpadding="0" width="100%" bgcolor="#f2f3f8"
                  style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;">
                  <tr>
                      <td>
                          <table style="background-color: #f2f3f8; max-width:670px;  margin:0 auto;" width="100%" border="0" align="center" cellpadding="0" cellspacing="0">
                              <tr>
                                  <td>
                                      <table width="95%" border="0" align="center" cellpadding="0" cellspacing="0"
                                          style="max-width:670px;background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                          <tr>
                                              <td style="height:40px;">&nbsp;</td>
                                          </tr>
                                          <tr>
                                              <td style="padding:0 35px;">
                                                  <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">You have requested to reset your password</h1>
                                                  <span style="display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;"></span>
                                                  <p style="color:#455056; font-size:15px; line-height:24px; margin:0;">
                                                  Dear ${payload.firstName}, to reset your password, please click the link to verify your identity and set a new password for your account.
                                                  </p>
                                                  <a href="${payload.PRLink}" style="background:#20e277;text-decoration:none !important; font-weight:500; margin:35px 0px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px;">Click here to reset your password</a>
                                                  
                                                  <p style="color:#455056; font-size:15px; line-height:24px; margin:0;">
                                                  If the button above isn't working, paste the link below into your browser:
                                                  </p>
                                                  <p>${payload.PRLink}</p>
                                                  <p style="color:#455056; font-size:15px; line-height:24px; margin:0;">
                                                  This link will expire in 30 minutes. If you did not request a reset, you can safely ignore this email.
                                                  </p>
                                              </td>
                                          </tr>
                                          <tr>
                                              <td style="height:40px;">&nbsp;</td>
                                          </tr>
                                      </table>
                                  </td>
                              </tr>
                          </table>
                      </td>
                  </tr>
              </table>
              <!--/100% body table-->
          </body>
      </html>`,
    };
//sends the email using the configured transporter..
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.log("Error while sending Email: ", err);
        return false;
      }
    });
    return true;
  } catch (error) {
    console.log("Error: ", error);
    return false;
  }
};