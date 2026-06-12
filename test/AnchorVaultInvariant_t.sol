// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

// ─────────────────────────────────────────────────────────────────────────────
//  ИНВАРИАНТ-ТЕСТ для AnchorVaultV45
//
//  Что он делает простыми словами:
//  Foundry сам, случайным образом, тысячи раз вызывает действия из Handler
//  (открыть / доложить / снять / закрыть сейф) в любом порядке и на любые суммы.
//  После КАЖДОГО действия проверяются два правила («инварианта»):
//
//   1) invariant_solvency
//      В контракте всегда лежит НЕ МЕНЬШЕ денег, чем он должен всем вместе
//      (принципал юзеров + комиссии создателя + резерв + пул наград).
//      Если хоть раз станет меньше — касса дырявая, тест красный.
//
//   2) invariant_lockedMatchesVault
//      Счётчик "сколько мы должны юзерам" (lockedPrincipal) всегда совпадает
//      с реальной суммой в открытом сейфе. Сейф закрыт — счётчик равен 0.
//
//  Запуск:  forge test --match-path test/AnchorVaultInvariant_t.sol -vv
// ─────────────────────────────────────────────────────────────────────────────

import {Test} from "forge-std/Test.sol";
import {AnchorVaultV45} from "../src/AnchorVaultV45.sol";
import {MockANCR} from "./mocks/MockANCR.sol";

// ─────────────────────────────────────────────────────────────────────────────
//  HANDLER — набор "разрешённых случайных действий", которые дёргает фаззер.
//  Все вызовы идут от имени Алисы. Сейф у Алисы максимум один (по токену ANCR),
//  поэтому Handler сам помнит: открыт сейф или нет, и его id.
// ─────────────────────────────────────────────────────────────────────────────
contract InvariantHandler is Test {
    AnchorVaultV45 internal vault;
    MockANCR internal ancr;

    address public actor;            // Алиса
    uint256 internal aMainPk;        // приватный ключ "основного" ключа сейфа
    uint256 internal aRecPk;         // приватный ключ "ключа восстановления"
    address internal aMain;
    address internal aRec;

    bool    public isOpen;           // открыт ли сейчас сейф
    uint256 public currentVid;       // id текущего сейфа

    // те же typehash, что в контракте и в основном тесте
    bytes32 constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address owner,uint256 vaultId,uint256 amount,address to,uint64 nonce,uint256 deadline)");
    bytes32 constant EARLY_CLOSE_TYPEHASH =
        keccak256("EarlyClose(address owner,uint256 vaultId,uint64 nonce,uint256 deadline)");

    constructor(
        AnchorVaultV45 _vault,
        MockANCR _ancr,
        address _actor,
        uint256 _aMainPk,
        uint256 _aRecPk
    ) {
        vault   = _vault;
        ancr    = _ancr;
        actor   = _actor;
        aMainPk = _aMainPk;
        aRecPk  = _aRecPk;
        aMain   = vm.addr(_aMainPk);
        aRec    = vm.addr(_aRecPk);
    }

    // ── подпись EIP-712 (как в основном тесте) ──────────────────────────────
    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ── ДЕЙСТВИЕ 1: открыть сейф (только если закрыт) ───────────────────────
    function openVault(uint256 amount) public {
        if (isOpen) return;
        uint256 minD = vault.MIN_DEPOSIT();
        uint256 bal  = ancr.balanceOf(actor);
        if (bal < minD * 2) return;                 // не хватает на минимальный вклад
        amount = bound(amount, minD * 2, bal);      // запас, чтобы пройти комиссию открытия

        AnchorVaultV45.VaultParams memory p = AnchorVaultV45.VaultParams({
            name: "V",
            mainAuthKey: aMain,
            recoveryAuthKey: aRec,
            amount: amount
        });

        vm.prank(actor);
        vault.openVault(address(ancr), p, 0);       // level 0 = SAFE, таймлок 0
        currentVid = vault.activeVaultIdByToken(actor, address(ancr));
        isOpen = true;
    }

    // ── ДЕЙСТВИЕ 2: доложить в сейф ─────────────────────────────────────────
    function deposit(uint256 amount) public {
        if (!isOpen) return;
        uint256 minD = vault.MIN_DEPOSIT();
        uint256 bal  = ancr.balanceOf(actor);
        if (bal < minD * 2) return;
        amount = bound(amount, minD * 2, bal);

        vm.prank(actor);
        vault.depositToVault(currentVid, amount);
    }

    // ── ДЕЙСТВИЕ 3: снять часть/всё (подпись основным ключом) ───────────────
    function withdraw(uint256 amount) public {
        if (!isOpen) return;
        (,, uint120 amt,, uint8 status,) = vault.getVaultCore(actor, currentVid);
        if (status != 0 || amt == 0) { isOpen = false; return; }
        amount = bound(amount, 1, amt);

        (uint64 nonce,,) = vault.getVaultAuth(actor, currentVid);
        bytes32 sh = keccak256(abi.encode(
            WITHDRAW_TYPEHASH, actor, currentVid, amount, actor, nonce, type(uint256).max
        ));
        bytes memory sig = _sign(aMainPk, sh);

        vm.prank(actor);
        vault.withdrawFromVault(currentVid, amount, actor, type(uint256).max, sig);

        if (amount == amt) isOpen = false;          // сняли всё — сейф закрылся
    }

    // ── ДЕЙСТВИЕ 4: досрочно закрыть (подпись ключом восстановления) ────────
    function earlyClose() public {
        if (!isOpen) return;
        (,,,, uint8 status,) = vault.getVaultCore(actor, currentVid);
        if (status != 0) { isOpen = false; return; }

        (uint64 nonce,,) = vault.getVaultAuth(actor, currentVid);
        bytes32 sh = keccak256(abi.encode(
            EARLY_CLOSE_TYPEHASH, actor, currentVid, nonce, type(uint256).max
        ));
        bytes memory sig = _sign(aRecPk, sh);

        vm.prank(actor);
        vault.earlyClose(currentVid, type(uint256).max, sig);
        isOpen = false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  САМ ТЕСТ — деплоит контракт, регистрирует Handler как источник случайных
//  действий и после каждого шага проверяет инварианты.
// ─────────────────────────────────────────────────────────────────────────────
contract AnchorVaultInvariantTest is Test {
    AnchorVaultV45 vault;
    MockANCR ancr;
    InvariantHandler handler;

    address creator      = address(0xC0);
    address guardian     = address(0x6A);
    address payoutWallet = address(0xBEEF01);
    address alice        = address(0xA11CE);
    address aliceEmergency = address(0xE1);

    uint256 aMainPk = 0xA11CE0001;
    uint256 aRecPk  = 0xA11CE0002;

    function setUp() public {
        vm.prank(creator);
        ancr = new MockANCR(10_000_000 ether);

        vm.prank(creator);
        vault = new AnchorVaultV45(address(ancr), guardian, payoutWallet);

        vm.prank(creator);
        ancr.transfer(alice, 1_000_000 ether);

        // Алиса один раз разрешает контракту списывать токены и задаёт аварийный адрес
        vm.prank(alice);
        ancr.approve(address(vault), type(uint256).max);
        vm.prank(alice);
        vault.setGlobalEmergency(aliceEmergency);

        handler = new InvariantHandler(vault, ancr, alice, aMainPk, aRecPk);

        // фаззер дёргает только функции Handler, а не контракт напрямую
        targetContract(address(handler));
    }

    // ПРАВИЛО 1: касса не дырявая — лежит не меньше, чем должны всем
    function invariant_solvency() public view {
        uint256 bal = ancr.balanceOf(address(vault));
        uint256 owed =
            vault.lockedPrincipal(address(ancr)) +
            vault.creatorFees(address(ancr)) +
            vault.strategicReserve(address(ancr)) +
            vault.rewardPool(address(ancr));
        assertGe(bal, owed, "INSOLVENT: kassa hranit menshe, chem dolzhna");
    }

    // ПРАВИЛО 2: счётчик долга юзеру совпадает с суммой в сейфе
    function invariant_lockedMatchesVault() public view {
        uint256 locked = vault.lockedPrincipal(address(ancr));
        if (handler.isOpen()) {
            (,, uint120 amt,,,) = vault.getVaultCore(handler.actor(), handler.currentVid());
            assertEq(locked, amt, "lockedPrincipal != summa v seyfe");
        } else {
            assertEq(locked, 0, "lockedPrincipal dolzhen byt 0 pri zakrytom seyfe");
        }
    }
}
