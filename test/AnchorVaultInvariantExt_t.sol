// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

// ════════════════════════════════════════════════════════════════════════════
//  AnchorVaultCoin — РАСШИРЕННЫЙ ИНВАРИАНТ-ТЕСТ (мульти-актор + злые токены)
//
//  Чем отличается от базового AnchorVaultInvariant_t.sol:
//   • 3 актора (Алиса, Боб, Кэрол) вместо одного → можно фаззить ПЕРЕВОДЫ
//   • 4 токена: ANCR(18), USDC-like(6), FeeOnTransfer, Rebasing → мульти-токен
//   • Действия: open/deposit/withdraw/earlyClose/transferVault/secureTransfer/
//     panic + смена паузы (guardian)
//   • Инварианты: solvency ПО ВСЕМ токенам + согласованность состояний
//
//  Запуск (Foundry):  forge test --match-path test/AnchorVaultInvariantExt_t.sol -vv
//  Запуск (Medusa):   поменяй в medusa.json targetContracts на ["AnchorVaultInvariantExtTest"]
//
//  ВАЖНО: злые токены встроены прямо здесь (не зависят от твоих моков),
//  чтобы файл гарантированно скомпилировался сам по себе.
// ════════════════════════════════════════════════════════════════════════════

import {Test} from "forge-std/Test.sol";
import {AnchorVaultCoin} from "../src/AnchorVaultCoin.sol";

// ─────────────────────────────────────────────────────────────────────────────
//  ВСТРОЕННЫЕ ТОКЕНЫ
// ─────────────────────────────────────────────────────────────────────────────

// Обычный ERC20 с настраиваемыми decimals (для ANCR=18 и USDC-like=6)
contract TToken {
    string public name = "TT";
    string public symbol = "TT";
    uint8 public immutable decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint8 _dec, uint256 _supply) {
        decimals = _dec;
        totalSupply = _supply;
        balanceOf[msg.sender] = _supply;
    }
    function transfer(address to, uint256 v) public virtual returns (bool) {
        balanceOf[msg.sender] -= v; balanceOf[to] += v; return true;
    }
    function approve(address s, uint256 v) public returns (bool) {
        allowance[msg.sender][s] = v; return true;
    }
    function transferFrom(address f, address t, uint256 v) public virtual returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max)
            allowance[f][msg.sender] -= v;
        balanceOf[f] -= v; balanceOf[t] += v; return true;
    }
    function burn(uint256 v) external { balanceOf[msg.sender] -= v; totalSupply -= v; }
}

// ЗЛОЙ #1: Fee-on-transfer — забирает 1% при КАЖДОМ переводе
contract FeeToken is TToken {
    constructor(uint256 s) TToken(18, s) {}
    function transfer(address to, uint256 v) public override returns (bool) {
        uint256 fee = v / 100;                 // 1% «сгорает»
        balanceOf[msg.sender] -= v;
        balanceOf[to] += (v - fee);
        balanceOf[address(0xdead)] += fee;
        return true;
    }
    function transferFrom(address f, address t, uint256 v) public override returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max)
            allowance[f][msg.sender] -= v;
        uint256 fee = v / 100;
        balanceOf[f] -= v;
        balanceOf[t] += (v - fee);
        balanceOf[address(0xdead)] += fee;
        return true;
    }
}

// ЗЛОЙ #2: Rebasing — баланс контракта можно «ужать» извне (rebaseDown)
contract RebaseToken is TToken {
    constructor(uint256 s) TToken(18, s) {}
    // эмулируем отрицательный ребейс: режем баланс цели на N%
    function rebaseDown(address target, uint256 pctBps) external {
        uint256 b = balanceOf[target];
        uint256 cut = (b * pctBps) / 10000;
        balanceOf[target] -= cut;
        balanceOf[address(0xdead)] += cut;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  HANDLER — случайные действия для фаззера (мульти-актор, мульти-токен)
// ─────────────────────────────────────────────────────────────────────────────
contract ExtHandler is Test {
    AnchorVaultCoin internal vault;

    // токены
    TToken      internal ancr;     // 18 decimals (главный)
    TToken      internal usdc;     // 6 decimals
    FeeToken    internal feeTok;   // fee-on-transfer
    RebaseToken internal rebTok;   // rebasing
    address[4]  internal tokens;

    // акторы (3 юзера со своими ключами)
    struct Actor { address addr; uint256 ownerPk; uint256 mainPk; uint256 recPk; address main; address rec; address emergency; }
    Actor[3] internal actors;

    bytes32 constant ACCEPT_TRANSFER_TYPEHASH =
        keccak256("AcceptVaultTransfer(address from,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint256 deadline)");
    bytes32 constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 constant EARLY_CLOSE_TYPEHASH =
        keccak256("EarlyClose(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");
    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferVault(address owner,uint256 vaultId,address to,address newMainKey,address newRecoveryKey,uint64 nonce,uint256 deadline)");

    address internal guardian;

    constructor(
        AnchorVaultCoin _vault,
        TToken _ancr, TToken _usdc, FeeToken _fee, RebaseToken _reb,
        address _guardian
    ) {
        vault = _vault;
        ancr = _ancr; usdc = _usdc; feeTok = _fee; rebTok = _reb;
        tokens = [address(_ancr), address(_usdc), address(_fee), address(_reb)];
        guardian = _guardian;
    }

    function _setActor(uint256 i, uint256 opk, uint256 mpk, uint256 rpk, address emg) external {
        actors[i] = Actor(vm.addr(opk), opk, mpk, rpk, vm.addr(mpk), vm.addr(rpk), emg);
    }

    function _sign(uint256 pk, bytes32 sh) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.domainSeparator(), sh));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _pickActor(uint256 seed) internal view returns (Actor memory) {
        return actors[seed % 3];
    }
    function _pickToken(uint256 seed) internal view returns (TToken) {
        return TToken(tokens[seed % 4]);
    }

    // ── открыть сейф (любой актор, любой токен) ─────────────────────────────
    function openVault(uint256 actorSeed, uint256 tokenSeed, uint256 amount, uint8 level) public {
        Actor memory ac = _pickActor(actorSeed);
        TToken tok = _pickToken(tokenSeed);
        if (vault.activeVaultIdByToken(ac.addr, address(tok)) != 0) return;

        // нужен установленный globalEmergency
        if (vault.globalEmergency(ac.addr) == address(0)) {
            vm.prank(ac.addr);
            vault.setGlobalEmergency(ac.emergency);
        }

        uint256 bal = tok.balanceOf(ac.addr);
        uint256 minNeeded = 10 ** uint256(tok.decimals()) / 50; // с запасом > minDeposit
        if (bal < minNeeded) return;
        amount = bound(amount, minNeeded, bal);
        level = uint8(bound(level, 0, 2));

        AnchorVaultCoin.VaultParams memory p = AnchorVaultCoin.VaultParams({
            mainAuthKey: ac.main, recoveryAuthKey: ac.rec, amount: amount
        });
        vm.prank(ac.addr);
        try vault.openVault(address(tok), p, level) {} catch {}
    }

    // ── доложить ────────────────────────────────────────────────────────────
    function deposit(uint256 actorSeed, uint256 tokenSeed, uint256 amount) public {
        Actor memory ac = _pickActor(actorSeed);
        TToken tok = _pickToken(tokenSeed);
        uint256 vid = vault.activeVaultIdByToken(ac.addr, address(tok));
        if (vid == 0) return;
        uint256 bal = tok.balanceOf(ac.addr);
        uint256 minNeeded = 10 ** uint256(tok.decimals()) / 50;
        if (bal < minNeeded) return;
        amount = bound(amount, minNeeded, bal);
        vm.prank(ac.addr);
        try vault.depositToVault(vid, amount) {} catch {}
    }

    // ── снять (подпись main) ─────────────────────────────────────────────────
    function withdraw(uint256 actorSeed, uint256 tokenSeed, uint256 amount) public {
        Actor memory ac = _pickActor(actorSeed);
        TToken tok = _pickToken(tokenSeed);
        uint256 vid = vault.activeVaultIdByToken(ac.addr, address(tok));
        if (vid == 0) return;
        (,, uint120 amt, uint8 status,) = vault.getVaultCore(ac.addr, vid);
        if (status != 0 || amt == 0) return;
        amount = bound(amount, 1, amt);
        (uint64 nonce,,) = vault.getVaultAuth(ac.addr, vid);
        bytes32 sh = keccak256(abi.encode(
            WITHDRAW_TYPEHASH, ac.addr, vid, amount, ac.addr, nonce, type(uint256).max));
        bytes memory sig = _sign(ac.mainPk, sh);
        vm.prank(ac.addr);
        try vault.withdrawFromVault(vid, amount, ac.addr, type(uint256).max, sig) {} catch {}
    }

    // ── досрочно закрыть (подпись recovery) ──────────────────────────────────
    function earlyClose(uint256 actorSeed, uint256 tokenSeed) public {
        Actor memory ac = _pickActor(actorSeed);
        TToken tok = _pickToken(tokenSeed);
        uint256 vid = vault.activeVaultIdByToken(ac.addr, address(tok));
        if (vid == 0) return;
        (,,, uint8 status,) = vault.getVaultCore(ac.addr, vid);
        if (status != 0) return;
        (uint64 nonce,,) = vault.getVaultAuth(ac.addr, vid);
        bytes32 sh = keccak256(abi.encode(EARLY_CLOSE_TYPEHASH, ac.addr, vid, nonce, type(uint256).max));
        bytes memory sig = _sign(ac.recPk, sh);
        vm.prank(ac.addr);
        try vault.earlyClose(vid, type(uint256).max, sig) {} catch {}
    }

    // ── panic (без подписи) ──────────────────────────────────────────────────
    function panic(uint256 actorSeed, uint256 tokenSeed) public {
        Actor memory ac = _pickActor(actorSeed);
        TToken tok = _pickToken(tokenSeed);
        uint256 vid = vault.activeVaultIdByToken(ac.addr, address(tok));
        if (vid == 0) return;
        vm.prank(ac.addr);
        try vault.panicWithdraw(vid) {} catch {}
    }

    // ── быстрый перевод сейфа другому актору (подпись main) ──────────────────
    function transferVault(uint256 fromSeed, uint256 toSeed, uint256 tokenSeed) public {
        Actor memory from = _pickActor(fromSeed);
        Actor memory to   = _pickActor(toSeed + 1);   // сдвиг чтобы не себе
        if (from.addr == to.addr) return;
        TToken tok = _pickToken(tokenSeed);
        uint256 vid = vault.activeVaultIdByToken(from.addr, address(tok));
        if (vid == 0) return;
        (,,, uint8 status,) = vault.getVaultCore(from.addr, vid);
        if (status != 0) return;
        if (vault.activeVaultIdByToken(to.addr, address(tok)) != 0) return;
        if (vault.globalEmergency(to.addr) == address(0)) {
            vm.prank(to.addr);
            vault.setGlobalEmergency(to.emergency);
        }
        (uint64 nonce,,) = vault.getVaultAuth(from.addr, vid);
        bytes32 sh = keccak256(abi.encode(
            TRANSFER_TYPEHASH, from.addr, vid, to.addr, to.main, to.rec, nonce, type(uint256).max));
        bytes memory sig = _sign(from.mainPk, sh);
        vm.prank(from.addr);
        bytes32 ah = keccak256(abi.encode(
            ACCEPT_TRANSFER_TYPEHASH, from.addr, vid, to.addr, to.main, to.rec, type(uint256).max));
        bytes memory acc = _sign(to.ownerPk, ah);
        try vault.transferVault(vid, to.addr, to.main, to.rec, type(uint256).max, sig, acc) {} catch {}
    }

    // ── ЗЛОЕ ДЕЙСТВИЕ: ребейз вниз на балансе контракта ──────────────────────
    // Проверяем: ломает ли отрицательный ребейс инвариант solvency для rebTok.
    function rebaseAttack(uint256 pctBps) public {
        pctBps = bound(pctBps, 1, 5000);  // до 50% вниз
        rebTok.rebaseDown(address(vault), pctBps);
    }

    // ── смена паузы (guardian) ───────────────────────────────────────────────
    function togglePause(bool on) public {
        if (on) {
            vm.prank(guardian);
            try vault.emergencyPause() {} catch {}
        } else {
            vm.prank(guardian);
            try vault.unpause() {} catch {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ТЕСТ — деплой, раздача токенов, регистрация Handler, инварианты
// ─────────────────────────────────────────────────────────────────────────────
contract AnchorVaultInvariantExtTest is Test {
    AnchorVaultCoin vault;
    TToken ancr; TToken usdc; FeeToken feeTok; RebaseToken rebTok;
    ExtHandler handler;

    address creator      = address(0xC0);
    address guardian     = address(0x6A);
    address payoutWallet = address(0xBEEF01);

    // 3 актора
    uint256 aO = 0xA11CE00; address alice = vm.addr(aO); uint256 aM = 0xA11CE01; uint256 aR = 0xA11CE02;
    uint256 bO = 0xB0B00;   address bob   = vm.addr(bO); uint256 bM = 0xB0B01;   uint256 bR = 0xB0B02;
    uint256 cO = 0xCA20100; address carol = vm.addr(cO); uint256 cM = 0xCA2011;  uint256 cR = 0xCA2012;

    function setUp() public {
        // токены
        vm.startPrank(creator);
        ancr   = new TToken(18, 100_000_000 ether);
        usdc   = new TToken(6,  100_000_000 * 1e6);
        feeTok = new FeeToken(100_000_000 ether);
        rebTok = new RebaseToken(100_000_000 ether);
        vm.stopPrank();

        // vault на ANCR
        vm.prank(creator);
        vault = new AnchorVaultCoin(address(ancr), guardian, payoutWallet);

        // creator добавляет остальные токены в поддержку
        vm.startPrank(creator);
        vault.addSupportedToken(address(usdc));
        vault.addSupportedToken(address(feeTok));
        vault.addSupportedToken(address(rebTok));
        vm.stopPrank();

        // раздать токены акторам + апрувы
        address[3] memory acs = [alice, bob, carol];
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(creator);
            ancr.transfer(acs[i],   5_000_000 ether);
            usdc.transfer(acs[i],   5_000_000 * 1e6);
            feeTok.transfer(acs[i], 5_000_000 ether);
            rebTok.transfer(acs[i], 5_000_000 ether);
            vm.stopPrank();

            vm.startPrank(acs[i]);
            ancr.approve(address(vault), type(uint256).max);
            usdc.approve(address(vault), type(uint256).max);
            feeTok.approve(address(vault), type(uint256).max);
            rebTok.approve(address(vault), type(uint256).max);
            vm.stopPrank();
        }

        handler = new ExtHandler(vault, ancr, usdc, feeTok, rebTok, guardian);
        handler._setActor(0, aO, aM, aR, address(0xE1));
        handler._setActor(1, bO, bM, bR, address(0xE2));
        handler._setActor(2, cO, cM, cR, address(0xE3));

        targetContract(address(handler));
    }

    // ── ГЛАВНЫЙ ИНВАРИАНТ: solvency по ВСЕМ 4 токенам ───────────────────────
    function invariant_solvency_allTokens() public view {
        _checkSolvency(address(ancr));
        _checkSolvency(address(usdc));
        _checkSolvency(address(feeTok));
        // ВНИМАНИЕ: rebTok НАМЕРЕННО исключён из строгой проверки —
        // отрицательный ребейс физически уменьшает баланс, и solvency
        // для ребейс-токена держаться НЕ обязана (это известное свойство).
        // Если хочешь проверить «ловит ли контракт ребейс» — раскомментируй:
        // _checkSolvency(address(rebTok));
    }

    function _checkSolvency(address tok) internal view {
        uint256 bal = TToken(tok).balanceOf(address(vault));
        uint256 owed =
            vault.lockedPrincipal(tok) +
            vault.creatorFees(tok) +
            vault.strategicReserve(tok) +
            vault.rewardPool(tok);
        assertGe(bal, owed, "INSOLVENT for token");
    }

    // ── роли никогда не сливаются ────────────────────────────────────────────
    function invariant_rolesNeverMerge() public view {
        assertTrue(vault.creator() != vault.guardian(), "roles merged");
    }

    // ── totalBurned монотонно (не убывает) ───────────────────────────────────
    uint256 private _lastBurn;
    function invariant_burnMonotonic() public {
        uint256 cur = vault.totalBurnedANCR();
        assertGe(cur, _lastBurn, "burn decreased");
        _lastBurn = cur;
    }
}
