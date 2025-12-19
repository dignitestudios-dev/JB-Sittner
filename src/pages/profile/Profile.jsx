import React, { useContext, useEffect, useState } from "react";
import PasswordUpdate from "../../components/Profile/PasswordUpdate";
import { NavLink, useLocation } from "react-router-dom";
import UpdatePasswordModal from "../../components/Auth/UpdatePasswordModal";
import { FaEyeSlash, FaRegEye } from "react-icons/fa";
import { MyContext } from "../../context/GlobalContext";
import DeleteEmpProfile from "../../components/Profile/DeleteProfile";
import {
  collection,
  db,
  getDocs,
  query,
  where,
} from "../../firbase/FirebaseInit";
export default function Profile() {
  const [showPassword, setShowPassword] = useState(false);
  const { Employee, setIsDeleteProfile, setDeleteEmpId, setDeleteDocId } =
    useContext(MyContext);
  const [member, setMember] = useState({});
  const location = useLocation();

  const getMemberRec = async () => {
    const employeesRef = collection(db, "employee");
    const employeeQuery = query(
      employeesRef,
      where("id", "==", location?.state?.id)
    );
    const querySnapshot = await getDocs(employeeQuery);
    const employeeData = querySnapshot.docs.map((doc) => ({
      docId: doc.id,
      ...doc.data(),
    }));
    setMember(employeeData[0]);
  };

  useEffect(() => {
    getMemberRec();
  }, []);

  const DeleteEmp = () => {
    setIsDeleteProfile(true);
    setDeleteEmpId(member?.id);
    setDeleteDocId(member?.docId);
  };

  return (
    <div class="bg-[#F7F7F7] h-[90vh] py-3 px-3 lg:py-10 lg:px-10 ">
      <h2 class="font-semibold text-[24px] leading-[29px]">Profile</h2>
      <div class="bg-[#FFFFFF] border rounded-[10px] border-[#E4E4E4] mt-10 py-3 px-3 lg:py-5 lg:px-5">
        <div class="bg-[#F9FAFB] rounded-[10px] border border-[#E4E4E4] py-3 px-3 lg:py-5 lg:px-5">
          <div class="flex items-center justify-between flex-wrap ">
            <h2 class="font-medium text-[20px] leading-[24px]">
              Personal Information
            </h2>
            <div className="flex items-center gap-3  mt-3 lg:mt-0">
              <NavLink
                to={"/editmember"}
                state={{ id: member.id }}
                className="text-white bg-[#0A8A33]  rounded-lg flex items-center   px-5 py-2.5 text-center"
              >
                {" "}
                <img src="/Edit.png" width={15} /> Edit{" "}
              </NavLink>
              {Employee?.role == "admin" && (
                <button
                  onClick={() => DeleteEmp()}
                  className="text-white bg-[#EE3131]  rounded-lg flex items-center   px-5 py-2.5 text-center"
                >
                  {" "}
                  <img src="/whitebg-trash.png" className="mr-2" width={15} />
                  Delete{" "}
                </button>
              )}
            </div>
          </div>
          <div>
            <img
              src={member?.pic ? member?.pic : "noprofile.png"}
              className="rounded-full cursor-pointer w-[50px] h-[50px] object-cover"
              alt=""
            />
          </div>
          <div className="mt-5 grid grid-cols-1 gap-5  lg:grid-cols-3">
            <div>
              <h2 className="text-[#787F8C] text-sm mb-2 font-semibold leading-[16.94px] uppercase">
                Name
              </h2>
              <p className="text-sm mb-1 leading-[16.94px]">{member?.name}</p>
            </div>
            <div>
              <h2 className="text-[#787F8C] text-sm mb-2 font-semibold leading-[16.94px] uppercase">
                Email
              </h2>
              <p className="text-sm mb-1 leading-[16.94px]">{member?.email}</p>
            </div>
            <div>
              <h2 className="text-[#787F8C] text-sm mb-2 font-semibold leading-[16.94px] uppercase">
                Contact No{" "}
              </h2>
              <p className="text-sm mb-1 leading-[16.94px]">
                {member?.contact}
              </p>
            </div>
            <div>
              <h2 className="text-[#787F8C] text-sm mb-2 font-semibold leading-[16.94px] uppercase">
                Address{" "}
              </h2>
              <p className="text-sm mb-1 leading-[16.94px]">
                {member?.address}
              </p>
            </div>
            {Employee?.role == "admin" && (
              <div className="" >
                <h2 className="text-[#787F8C] text-sm mb-2 font-semibold leading-[16.94px] uppercase">
                  Password{" "}
                </h2>
                <div className="flex items-center relative">
                  <input
                    type={!showPassword ? "password" : "text"}
                    className={`bg-transparent custom-input ${!showPassword ? "w-[110px]" : "w-auto"} `}
                    value={member?.password}
                    disabled
                  />
                 <div className="" >
                  {showPassword ? (
                    <div onClick={() => setShowPassword(!showPassword)}>
                      {" "}
                      <FaEyeSlash className="text-gray-300 cursor-pointer" />
                    </div>
                  ) : (
                    <div onClick={() => setShowPassword(!showPassword)}>
                      <FaRegEye className="text-gray-300 cursor-pointer" />
                    </div>
                  )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        <div>
          {Employee?.role == "user" && <PasswordUpdate />}
          <DeleteEmpProfile />
        </div>
      </div>
      <UpdatePasswordModal />
    </div>
  );
}
