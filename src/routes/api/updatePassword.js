import * as auth from '$lib/apis/auth-api-methods';
import { serverResponse } from '$lib/utils/helpers';

export async function post(request) {

  // NOTE - used by logged-in users updating password via /account page

  try {
    const { token, user } = request.locals;
    const { currentPassword, newPassword } = request.body;
    
    // authorize request
    const accessTokenCheck = await auth.verifyCurrentToken(token); // validate user session
    if(!accessTokenCheck.ok) throw { statusMessage: 'error', errorMessage: 'Unauthorized Session' };
    
    const authCheck = await auth.loginUser(user.email, currentPassword); // validate user entered password
    if(authCheck.error) throw { statusMessage: authCheck.statusMessage, errorMessage: 'Please double-check current password.' };

    const emailMatch = (accessTokenCheck.email === user.email); // compare returned email to user email in session
    if(!emailMatch) throw { statusMessage: 'error', errorMessage: 'Unauthorized User' };
    
    if(accessTokenCheck.ok && authCheck && emailMatch) {
    
      // Attempt to update password
      // -------------------------------------------------------------------------------------------
      const updatePassword = await auth.updateUser(token, { password: newPassword });

      // there does not seem to be an explicit response from Netlify Identity
      // when a user value has been successfully updated;
      // on success, the standard user object is returned; e.g. -
      // 
      // { "id": "some-id-value",
      //   "aud": "",
      //   "role": "",
      //   "email": "name@domain.com",
      //   "confirmed_at": "2021-01-01T01:00:00Z",
      //   "confirmation_sent_at": "2021-01-01T01:00:00Z",
      //   "app_metadata": { "provider": "email" },
      //   "user_metadata": {},
      //   "created_at": "2021-01-01T01:00:00Z",
      //   "updated_at": "2021-01-01T01:00:00.000001Z" }

      // currently testing for success implicitly via lack of
      // updatePassword.error and existence of 'email' in response object

      if (!updatePassword.error && updatePassword.email) {
        return serverResponse(200, true, {
          accountEmail: updatePassword.email,
        })
      }
    }

  } catch (error) {
    let { statusMessage, errorMessage } = error;
    if (!errorMessage) console.log(new Date().toISOString(), "💥 'updatePassword' endpoint unsuccessful : error.message :", error.message);

    if (errorMessage?.toLowerCase().includes('bad request')) {
      errorMessage = 'We encountered a system error - please try again.'
    };
    if (errorMessage?.toLowerCase().includes('user not found')) {
      errorMessage = 'Please double-check current password.'
    };

    return serverResponse(200, false, {
      statusMessage: statusMessage || 'error',
      error: errorMessage || 'Unsuccessful Request',
    });
  }

}