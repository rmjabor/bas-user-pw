(function () {
  'use strict';

  const STORAGE_KEYS = {
    RESET_EMAIL: 'basupw_mock_reset_email_v1',
    LOGIN_GUARD: 'basupw_login_guard_v1',
    PENDING_LOGIN_EMAIL: 'basupw_pending_login_email_v1'
  };

  const LOGIN_MAX_ATTEMPTS = 5;
  const LOGIN_LOCK_MINUTES = 15;
  const ASCII_PRINTABLE_NO_CONTROL_REGEX = /^[\x20-\x7E]*$/;
  const MULTIPLE_MIDDLE_SPACES_REGEX = /\S\s{2,}\S/;
  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  const COMMON_BREACHED_PASSWORDS = new Set([
    '123456789012',
    '1234567890123',
    '12345678901234',
    '123456789012345',
    '1234567890123456',
    '1234567890ab',
    'aaaaaaaaaaaa',
    'abababababab',
    'adminadminadmin',
    'letmeinletmein',
    'password1234',
    'password12345',
    'password123456',
    'qwerty123456',
    'qwertyuiop123',
    'welcome123456'
  ]);

  function qs(id) {
    return document.getElementById(id);
  }

  function getSupabaseClient() {
    return window.basupwSupabase || window.supabaseClient || null;
  }

  function getBootstrapModal(element) {
    if (!element || !window.bootstrap || !window.bootstrap.Modal) return null;
    return window.bootstrap.Modal.getOrCreateInstance(element);
  }

  function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
  }

  function looksLikeEmail(email) {
    return EMAIL_REGEX.test(String(email || '').trim());
  }

  function stripNonPrintableAscii(value) {
    return Array.from(String(value || '')).filter(char => {
      const code = char.charCodeAt(0);
      return code >= 32 && code <= 126;
    }).join('');
  }

  function getTrimmedPassword(password) {
    return String(password || '').replace(/^\s+|\s+$/g, '');
  }

  function getPasswordLengthForPolicy(password) {
    return getTrimmedPassword(password).length;
  }

  function isAsciiPrintablePassword(password) {
    return ASCII_PRINTABLE_NO_CONTROL_REGEX.test(String(password || ''));
  }

  function hasMultipleMiddleSpaces(password) {
    return MULTIPLE_MIDDLE_SPACES_REGEX.test(String(password || ''));
  }

  function hasRepeatedSequence(text) {
    return /(.)\1{3,}/.test(text) || /(..+)\1{2,}/.test(text);
  }

  function hasKeyboardSequence(text) {
    const lower = text.toLowerCase();
    const sequences = [
      'abcdefghijklmnopqrstuvwxyz',
      'zyxwvutsrqponmlkjihgfedcba',
      '0123456789',
      '9876543210',
      'qwertyuiop',
      'poiuytrewq',
      'asdfghjkl',
      'lkjhgfdsa',
      'zxcvbnm',
      'mnbvcxz'
    ];

    return sequences.some(sequence => {
      for (let i = 0; i <= sequence.length - 4; i += 1) {
        if (lower.includes(sequence.slice(i, i + 4))) return true;
      }
      return false;
    });
  }

  function countCharacterClasses(text) {
    let count = 0;
    if (/[a-z]/.test(text)) count += 1;
    if (/[A-Z]/.test(text)) count += 1;
    if (/\d/.test(text)) count += 1;
    if (/[^A-Za-z0-9\s]/.test(text)) count += 1;
    if (/\s/.test(text)) count += 1;
    return count;
  }

  function isWeakPassword(password, context = {}) {
    const trimmed = getTrimmedPassword(password);
    const compact = trimmed.toLowerCase().replace(/\s+/g, '');
    const uniqueChars = new Set(trimmed).size;
    const emailLocal = normalizeEmail(context.email || '').split('@')[0] || '';
    const firstName = String(context.firstName || '').trim().toLowerCase();
    const lastName = String(context.lastName || '').trim().toLowerCase();

    if (!trimmed || trimmed.length < 12) return false;
    if (COMMON_BREACHED_PASSWORDS.has(compact)) return true;
    if (emailLocal && compact.includes(emailLocal.replace(/[^a-z0-9]/g, ''))) return true;
    if (firstName && compact.includes(firstName.replace(/[^a-z0-9]/g, ''))) return true;
    if (lastName && compact.includes(lastName.replace(/[^a-z0-9]/g, ''))) return true;
    if (hasRepeatedSequence(compact)) return true;
    if (hasKeyboardSequence(compact)) return true;
    if (uniqueChars <= 5) return true;
    if (countCharacterClasses(trimmed) <= 1) return true;
    if (trimmed.length < 14 && countCharacterClasses(trimmed) <= 2) return true;

    return false;
  }

  async function sha1Hex(message) {
    const data = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  }

  async function isPwnedPassword(password) {
    const trimmed = getTrimmedPassword(password);
    if (!trimmed || trimmed.length < 12 || !window.crypto?.subtle || !window.fetch) return false;

    try {
      const hash = await sha1Hex(trimmed);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        method: 'GET',
        headers: { 'Add-Padding': 'true' }
      });

      if (!response.ok) return false;
      const body = await response.text();
      return body.split('\n').some(line => line.split(':')[0]?.trim() === suffix);
    } catch (error) {
      console.warn('[BAS_UPW] Não foi possível consultar senhas vazadas no momento.', error);
      return false;
    }
  }

  function generatePrintableAsciiPassword(length = 20) {
    const chars = [];
    for (let code = 33; code <= 126; code += 1) {
      chars.push(String.fromCharCode(code));
    }
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, number => chars[number % chars.length]).join('');
  }

  function loadLoginGuard() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.LOGIN_GUARD);
      const parsed = raw ? JSON.parse(raw) : null;
      return { count: parsed?.count || 0, lockUntil: parsed?.lockUntil || 0 };
    } catch (error) {
      return { count: 0, lockUntil: 0 };
    }
  }

  function saveLoginGuard(data) {
    localStorage.setItem(STORAGE_KEYS.LOGIN_GUARD, JSON.stringify(data));
  }

  function clearLoginGuard() {
    localStorage.removeItem(STORAGE_KEYS.LOGIN_GUARD);
  }

  function getRemainingLockMinutes(lockUntil) {
    return Math.max(1, Math.ceil((lockUntil - Date.now()) / 60000));
  }

  function setButtonEnabledState(button, enabled) {
    if (!button) return;
    button.disabled = !enabled;
    button.style.opacity = enabled ? '1' : '0.55';
    button.style.cursor = enabled ? 'pointer' : 'not-allowed';
  }

  function setButtonText(button, text) {
    if (button) button.textContent = text;
  }

  function setHtmlVisibility(element, visible) {
    if (!element) return;
    element.classList.toggle('d-none', !visible);
    element.style.display = visible ? '' : 'none';
  }

  function togglePasswordVisibility(input, icon) {
    if (!input || !icon) return;
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    icon.classList.toggle('ion-eye', !reveal);
    icon.classList.toggle('ion-eye-disabled', reveal);
  }

  function sanitizePasswordInput(input) {
    if (!input) return;
    const sanitized = stripNonPrintableAscii(input.value);
    if (input.value !== sanitized) {
      const cursor = input.selectionStart;
      input.value = sanitized;
      if (typeof cursor === 'number') {
        const newPos = Math.min(cursor - 1, sanitized.length);
        input.setSelectionRange(Math.max(0, newPos), Math.max(0, newPos));
      }
    }
  }

  function buildPasswordWarningHtml(type) {
    if (type === 'weak') {
      return '<strong><span style="color: rgb(235, 68, 68);">Fraca:</span></strong>&nbsp;A senha que você escolheu é fraca e pode ser facilmente identificada. Considere usar uma senha mais forte.';
    }
    if (type === 'pwned') {
      return '<strong><span style="color: rgb(235, 68, 68);">Vazada:</span></strong>&nbsp;Identificamos que a senha escolhida já apareceu em vazamentos conhecidos. Considere usar uma senha diferente e exclusiva.';
    }
    return '';
  }

  function showInfo(message) {
    window.alert(message);
  }

  function createModalNoticeController(modalId, textId) {
    const element = qs(modalId);
    const textElement = qs(textId);
    const modal = getBootstrapModal(element);
    let onHidden = null;

    element?.addEventListener('hidden.bs.modal', () => {
      const callback = onHidden;
      onHidden = null;
      if (typeof callback === 'function') callback();
    });

    return {
      show(message, options = {}) {
        const { onClose = null } = options;
        if (!modal || !textElement) {
          showInfo(message);
          if (typeof onClose === 'function') onClose();
          return;
        }
        textElement.textContent = message;
        onHidden = typeof onClose === 'function' ? onClose : null;
        modal.show();
      },
      hide() { modal?.hide(); },
      element,
      modal,
      textElement
    };
  }

  function getBaseRedirectUrl() {
    const path = window.location.pathname;
    const lastSlash = path.lastIndexOf('/');
    const directory = lastSlash >= 0 ? path.slice(0, lastSlash + 1) : '/';
    return `${window.location.origin}${directory}`;
  }

  function buildPageUrl(page) {
    return `${getBaseRedirectUrl()}${page}`;
  }

  function getFriendlyAuthErrorMessage(error, fallback) {
    const message = String(error?.message || '').toLowerCase();
    if (message.includes('invalid login credentials')) return 'Não foi possível realizar o login. Verifique o e-mail e a senha.';
    if (message.includes('email not confirmed')) return 'Seu e-mail ainda não foi confirmado. Abra a mensagem enviada pelo BAS_UPW e clique no link de confirmação.';
    if (message.includes('user already registered')) return 'Já existe um usuário cadastrado com este e-mail. Digite outro e-mail, por favor.';
    if (message.includes('signup is disabled')) return 'O cadastro de novos usuários está indisponível no momento.';
    if (message.includes('password should be at least')) return 'A senha precisa ter pelo menos 12 caracteres.';
    if (message.includes('same password')) return 'Escolha uma senha diferente da atual.';
    if (message.includes('expired')) return 'O link expirou. Solicite um novo link de redefinição de senha.';
    if (message.includes('invalid') && message.includes('token')) return 'O link informado é inválido. Solicite um novo link de redefinição de senha.';
    return fallback || 'Não foi possível concluir a operação no momento.';
  }

  function createPasswordWatcher(config) {
    const input = qs(config.inputId);
    const warningLabel = qs(config.warningLabelId);
    const spacesLabel = config.spacesLabelId ? qs(config.spacesLabelId) : null;
    const emailInput = config.emailInputId ? qs(config.emailInputId) : null;
    const firstNameInput = config.firstNameInputId ? qs(config.firstNameInputId) : null;
    const lastNameInput = config.lastNameInputId ? qs(config.lastNameInputId) : null;
    let requestCounter = 0;
    let lastState = { weak: false, pwned: false };

    async function refresh() {
      if (!input) return lastState;

      sanitizePasswordInput(input);
      const password = input.value;
      const trimmedLength = getPasswordLengthForPolicy(password);
      const weak = trimmedLength >= 12 && isWeakPassword(password, {
        email: emailInput?.value,
        firstName: firstNameInput?.value,
        lastName: lastNameInput?.value
      });

      let pwned = false;
      const currentRequest = ++requestCounter;
      if (trimmedLength >= 12 && !weak) {
        pwned = await isPwnedPassword(password);
      }

      if (currentRequest !== requestCounter) return lastState;
      lastState = { weak, pwned };

      if (warningLabel) {
        const type = weak ? 'weak' : (pwned ? 'pwned' : '');
        warningLabel.innerHTML = buildPasswordWarningHtml(type);
        setHtmlVisibility(warningLabel, Boolean(type));
      }

      if (spacesLabel) {
        setHtmlVisibility(spacesLabel, hasMultipleMiddleSpaces(password));
      }

      if (typeof config.onStateChange === 'function') {
        config.onStateChange({
          weak,
          pwned,
          trimmedLength,
          hasMultipleMiddleSpaces: hasMultipleMiddleSpaces(password),
          password
        });
      }

      return lastState;
    }

    function queueRefresh() {
      window.clearTimeout(queueRefresh._timer);
      queueRefresh._timer = window.setTimeout(() => { refresh(); }, 350);
    }

    if (input) {
      input.addEventListener('input', queueRefresh);
      input.addEventListener('blur', () => refresh());
    }
    [emailInput, firstNameInput, lastNameInput].forEach(element => {
      if (element) element.addEventListener('input', queueRefresh);
    });

    setHtmlVisibility(warningLabel, false);
    setHtmlVisibility(spacesLabel, false);

    return { refresh, getState: () => lastState };
  }

  async function initCadastroPage() {
    const supabase = getSupabaseClient();
    const emailInput = qs('inputEmailCadastro');
    const firstNameInput = qs('inputNomeCadastro');
    const lastNameInput = qs('inputSobrenomeCadastro');
    const passwordInput = qs('inputSenhaCadastro');
    const showPasswordIcon = qs('icnMostrarSenhaCadastro');
    const generatePasswordButton = qs('btnGeneratePw');
    const termsCheck = qs('checkLiEconcordo');
    const submitButton = qs('btnCadastrar');
    const signupNotice = createModalNoticeController('mdlAvisosCadastro', 'txtAvisosCadastro');

    if (!emailInput || !firstNameInput || !lastNameInput || !passwordInput || !submitButton) return;
    if (!supabase) {
      setButtonEnabledState(submitButton, false);
      signupNotice.show('Não foi possível inicializar a conexão com o Supabase.');
      return;
    }

    const { data: sessionData } = await supabase.auth.getSession();
    if (sessionData?.session) {
      window.location.href = 'home.html';
      return;
    }

    const passwordWatcher = createPasswordWatcher({
      inputId: 'inputSenhaCadastro',
      warningLabelId: 'lblAvisoProbPw',
      spacesLabelId: 'lblAvisoMultiplosEspacos',
      emailInputId: 'inputEmailCadastro',
      firstNameInputId: 'inputNomeCadastro',
      lastNameInputId: 'inputSobrenomeCadastro',
      onStateChange: updateButtonState
    });

    function showSignupNotice(message, { redirectToLogin = false } = {}) {
      signupNotice.show(message, {
        onClose: redirectToLogin ? () => { window.location.href = 'entrar.html'; } : null
      });
    }

    function isPasswordValid() {
      return isAsciiPrintablePassword(passwordInput.value)
        && getPasswordLengthForPolicy(passwordInput.value) >= 12
        && getPasswordLengthForPolicy(passwordInput.value) <= 64;
    }

    function isFormFilled() {
      return [emailInput, firstNameInput, lastNameInput, passwordInput].every(input => String(input.value || '').trim() !== '')
        && !!termsCheck?.checked;
    }

    function updateButtonState() {
      const allFilled = isFormFilled();
      const emailValid = looksLikeEmail(emailInput.value);
      const passwordValid = isPasswordValid();
      const enabled = allFilled && emailValid && passwordValid;
      setButtonEnabledState(submitButton, enabled);
      if (enabled) setButtonText(submitButton, 'Cadastrar usuário');
      else if (!allFilled) setButtonText(submitButton, 'Preencha todos os campos e concorde com os termos');
      else setButtonText(submitButton, 'E-mail ou senha inválidos');
    }

    [emailInput, firstNameInput, lastNameInput].forEach(input => input.addEventListener('input', updateButtonState));
    termsCheck?.addEventListener('change', updateButtonState);
    passwordInput.addEventListener('input', updateButtonState);

    if (showPasswordIcon) {
      showPasswordIcon.addEventListener('click', () => togglePasswordVisibility(passwordInput, showPasswordIcon));
    }

    if (generatePasswordButton) {
      generatePasswordButton.addEventListener('click', () => {
        passwordInput.value = generatePrintableAsciiPassword(20);
        passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
      });
    }

    submitButton.addEventListener('click', async () => {
      await passwordWatcher.refresh();
      updateButtonState();
      if (submitButton.disabled) return;

      setButtonEnabledState(submitButton, false);
      setButtonText(submitButton, 'Cadastrando...');

      const payload = {
        email: String(emailInput.value || '').trim(),
        password: getTrimmedPassword(passwordInput.value),
        options: {
          emailRedirectTo: buildPageUrl('entrar.html'),
          data: {
            first_name: String(firstNameInput.value || '').trim(),
            last_name: String(lastNameInput.value || '').trim()
          }
        }
      };

      const { data, error } = await supabase.auth.signUp(payload);
      if (error) {
        const message = getFriendlyAuthErrorMessage(error, 'Não foi possível concluir o cadastro.');
        showSignupNotice(message.includes('Já existe um usuário')
          ? 'Já existe um usuário cadastrado com este e-mail. Digite outro e-mail, por favor.'
          : message);
        updateButtonState();
        return;
      }

      const identities = data?.user?.identities;
      if (Array.isArray(identities) && identities.length === 0) {
        showSignupNotice('Já existe um usuário cadastrado com este e-mail. Digite outro e-mail, por favor.');
        updateButtonState();
        return;
      }

      sessionStorage.setItem(STORAGE_KEYS.PENDING_LOGIN_EMAIL, payload.email);
      showSignupNotice('Cadastro realizado. Verifique seu e-mail para confirmar a conta antes de entrar.', { redirectToLogin: true });
    });

    updateButtonState();
    passwordWatcher.refresh();
  }

  async function initEntrarPage() {
    const supabase = getSupabaseClient();
    const forgotPasswordText = qs('txtEsqueciSenha');
    const emailInput = qs('inputEmailEntrar');
    const passwordInput = qs('inputSenhaEntrar');
    const showPasswordIcon = qs('icnMostrarSenhaEntrar');
    const submitButton = qs('btnEntrar');
    const signupButton = qs('btnCadastre');
    const enterNotice = createModalNoticeController('mdlAvisosEntrar', 'txtAvisosEntrar');
    const resetModal = getBootstrapModal(qs('mdlRedefSenha'));
    const resetEmailInput = qs('inputEmailLinkRedef');
    const sendResetButton = qs('btnEnviarLink');

    if (!emailInput || !passwordInput || !submitButton) return;
    if (!supabase) {
      setButtonEnabledState(submitButton, false);
      enterNotice.show('Não foi possível inicializar a conexão com o Supabase.');
      return;
    }

    const { data: sessionData } = await supabase.auth.getSession();
    if (sessionData?.session) {
      window.location.href = 'home.html';
      return;
    }

    const prefilledEmail = sessionStorage.getItem(STORAGE_KEYS.PENDING_LOGIN_EMAIL);
    if (prefilledEmail && !emailInput.value) {
      emailInput.value = prefilledEmail;
      sessionStorage.removeItem(STORAGE_KEYS.PENDING_LOGIN_EMAIL);
    }

    function isPasswordValid() {
      return isAsciiPrintablePassword(passwordInput.value)
        && getPasswordLengthForPolicy(passwordInput.value) >= 12
        && getPasswordLengthForPolicy(passwordInput.value) <= 64;
    }

    function updateLoginButton() {
      setButtonEnabledState(submitButton, looksLikeEmail(emailInput.value) && isPasswordValid());
    }

    function updateResetButton() {
      setButtonEnabledState(sendResetButton, looksLikeEmail(resetEmailInput?.value));
    }

    function showEnterNotice(text, options = {}) { enterNotice.show(text, options); }
    function showLoginError(text, options = {}) { showEnterNotice(text, options); }

    emailInput.addEventListener('input', updateLoginButton);
    passwordInput.addEventListener('input', () => {
      sanitizePasswordInput(passwordInput);
      updateLoginButton();
    });
    resetEmailInput?.addEventListener('input', updateResetButton);

    if (showPasswordIcon) {
      showPasswordIcon.addEventListener('click', () => togglePasswordVisibility(passwordInput, showPasswordIcon));
    }

    signupButton?.addEventListener('click', () => { window.location.href = 'cadastrar.html'; });

    forgotPasswordText?.addEventListener('click', () => {
      if (looksLikeEmail(emailInput.value)) resetEmailInput.value = String(emailInput.value || '').trim();
      updateResetButton();
      resetModal?.show();
    });

    sendResetButton?.addEventListener('click', async (event) => {
      event.preventDefault();
      if (!looksLikeEmail(resetEmailInput?.value)) return;

      const email = String(resetEmailInput.value || '').trim();
      setButtonEnabledState(sendResetButton, false);
      sendResetButton.textContent = 'Enviando...';

      const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo: buildPageUrl('resetpw.html') });

      sendResetButton.textContent = 'Enviar Link';
      updateResetButton();

      if (error) {
        console.error('[BAS_UPW] resetPasswordForEmail error:', error);
        showEnterNotice(error.message || 'Não foi possível enviar o link de redefinição de senha.');
        return;
      }

      sessionStorage.setItem(STORAGE_KEYS.RESET_EMAIL, email);
      resetModal?.hide();
      showEnterNotice('Enviamos o link de redefinição de senha para o e-mail informado.');
    });

    submitButton.addEventListener('click', async () => {
      updateLoginButton();
      if (submitButton.disabled) return;

      const guard = loadLoginGuard();
      if (guard.lockUntil > Date.now()) {
        showLoginError(`Excesso de tentativas de login sem sucesso. Tente novamente em ${getRemainingLockMinutes(guard.lockUntil)} minutos.`);
        return;
      }

      setButtonEnabledState(submitButton, false);
      setButtonText(submitButton, 'Entrando...');

      const { error } = await supabase.auth.signInWithPassword({
        email: String(emailInput.value || '').trim(),
        password: getTrimmedPassword(passwordInput.value)
      });

      if (error) {
        const nextCount = guard.count + 1;
        if (nextCount >= LOGIN_MAX_ATTEMPTS) {
          const lockUntil = Date.now() + (LOGIN_LOCK_MINUTES * 60000);
          saveLoginGuard({ count: nextCount, lockUntil });
          showLoginError(`Excesso de tentativas de login sem sucesso. Tente novamente em ${LOGIN_LOCK_MINUTES} minutos.`);
        } else {
          saveLoginGuard({ count: nextCount, lockUntil: 0 });
          showLoginError(getFriendlyAuthErrorMessage(error, 'Não foi possível realizar o login. Verifique o e-mail e a senha.'));
        }
        updateLoginButton();
        return;
      }

      clearLoginGuard();
      window.location.href = 'home.html';
    });

    updateLoginButton();
    updateResetButton();
  }

  async function initResetPage() {
    const supabase = getSupabaseClient();
    const passwordInput = qs('inputSenhaResetPw');
    const showPasswordIcon = qs('icnMostrarSenhaResetPw');
    const generatePasswordButton = qs('btnGenerateResetPw');
    const submitButton = qs('btnConfirmarResetPw');
    const resetNotice = createModalNoticeController('mdlAvisosResetPw', 'txtAvisosResetPw');

    if (!passwordInput || !submitButton) return;
    if (!supabase) {
      setButtonEnabledState(submitButton, false);
      resetNotice.show('Não foi possível inicializar a conexão com o Supabase.');
      return;
    }

    const passwordWatcher = createPasswordWatcher({
      inputId: 'inputSenhaResetPw',
      warningLabelId: 'lblAvisoProbResetPw',
      onStateChange: updateButtonState
    });

    function showResetNotice(message, options = {}) {
      resetNotice.show(message, options);
    }

    function isPasswordValid() {
      return isAsciiPrintablePassword(passwordInput.value)
        && getPasswordLengthForPolicy(passwordInput.value) >= 12
        && getPasswordLengthForPolicy(passwordInput.value) <= 64;
    }

    function updateButtonState() {
      setButtonEnabledState(submitButton, isPasswordValid());
    }

    passwordInput.addEventListener('input', updateButtonState);

    if (showPasswordIcon) {
      showPasswordIcon.addEventListener('click', () => togglePasswordVisibility(passwordInput, showPasswordIcon));
    }

    if (generatePasswordButton) {
      generatePasswordButton.addEventListener('click', () => {
        passwordInput.value = generatePrintableAsciiPassword(20);
        passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
      });
    }

    const { data: sessionData } = await supabase.auth.getSession();
    if (!sessionData?.session) {
      showResetNotice('Abra esta página pelo link de redefinição enviado ao seu e-mail.', {
        onClose: () => { window.location.href = 'entrar.html'; }
      });
      return;
    }

    submitButton.addEventListener('click', async () => {
      await passwordWatcher.refresh();
      updateButtonState();
      if (submitButton.disabled) return;

      setButtonEnabledState(submitButton, false);
      setButtonText(submitButton, 'Confirmando...');

      const { error } = await supabase.auth.updateUser({ password: getTrimmedPassword(passwordInput.value) });
      if (error) {
        showResetNotice(getFriendlyAuthErrorMessage(error, 'Não foi possível redefinir a senha.'));
        updateButtonState();
        return;
      }

      const resetEmail = sessionStorage.getItem(STORAGE_KEYS.RESET_EMAIL);
      if (resetEmail) {
        sessionStorage.setItem(STORAGE_KEYS.PENDING_LOGIN_EMAIL, resetEmail);
        sessionStorage.removeItem(STORAGE_KEYS.RESET_EMAIL);
      }
      await supabase.auth.signOut();
      showResetNotice('Senha redefinida com sucesso. Faça login novamente.', {
        onClose: () => { window.location.href = 'entrar.html'; }
      });
    });

    updateButtonState();
    passwordWatcher.refresh();
  }

  async function initHomePage() {
    const supabase = getSupabaseClient();
    const btnLogout = qs('btnLogoutHome');

    if (!btnLogout) return;
    if (!supabase) {
      setButtonEnabledState(btnLogout, false);
      console.error('[BAS_UPW] Não foi possível inicializar a conexão com o Supabase.');
      return;
    }

    btnLogout.addEventListener('click', async () => {
      try {
        console.log('[BAS_UPW] Logout iniciado');
        setButtonEnabledState(btnLogout, false);
        setButtonText(btnLogout, 'Saindo...');
        await supabase.auth.signOut();
        console.log('[BAS_UPW] Logout realizado');
        window.location.href = 'entrar.html';
      } catch (error) {
        console.error('[BAS_UPW] Erro no logout:', error);
        setButtonEnabledState(btnLogout, true);
        setButtonText(btnLogout, 'Logout');
      }
    });
  }

  function initSharedUiBehaviors() {
    const modalRedef = qs('mdlRedefSenha');
    const inputEmailRedef = qs('inputEmailLinkRedef');
    if (modalRedef && inputEmailRedef) {
      modalRedef.addEventListener('hidden.bs.modal', () => {
        inputEmailRedef.value = '';
      });
    }
  }

  document.addEventListener('DOMContentLoaded', async () => {
    initSharedUiBehaviors();
    await initCadastroPage();
    await initEntrarPage();
    await initResetPage();
    await initHomePage();
  });
})();
