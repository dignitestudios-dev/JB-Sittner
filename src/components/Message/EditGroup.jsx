import React, { useContext, useEffect, useState } from "react";
import { IoMdClose } from "react-icons/io";
import { MyContext } from "../../context/GlobalContext";
import { db, deleteDoc, deleteObject, doc, getDownloadURL, ref, storage, updateDoc, uploadBytesResumable } from "../../firbase/FirebaseInit";
import { toast } from "react-toastify";
export default function EditGroup() {
  const { isEditGroup, setEditGroup, GroupName } =
    useContext(MyContext);
  const [Image, setImage] = useState("");
  const [preview, setPreview] = useState();
  const [groupVal, setGroupVal] = useState(GroupName.group_name);
  const UpdateGroup = async (e) => {
    e.preventDefault();
    const myPromise = new Promise(async (resolve, reject) => {
      try {                
        const scheduledRef = doc(db, "group", GroupName.docId);
          const storageRef = ref(storage, `group/group-pic`);
          const uploadTask = uploadBytesResumable(storageRef, Image);
          uploadTask.on(
              "state_changed",
              null,
              (error) => {
                  reject(error.message);
              },
              async () => {
                  const downloadURL = await getDownloadURL(uploadTask.snapshot.ref);
                  await updateDoc(scheduledRef, {
                    group_name: groupVal,
                    groupimg: downloadURL,
                  });

                  resolve("Group Update");
              }
          );
      } catch (error) {
          reject(error.message);
      }
  });

  toast.promise(myPromise, {
      pending: "Updating Group...",
      success: (data) => data,
      error: (error) => error,
  }).then(() => {
    setEditGroup(false);
  });
  };

  useEffect(()=>{
    setGroupVal(GroupName.group_name)
  },[GroupName])
   
  useEffect(() => {
    if (!Image) {
        setPreview(undefined)
        return
    }
    const objectUrl = URL.createObjectURL(Image)
    setPreview(objectUrl)

    return () => URL.revokeObjectURL(objectUrl)
}, [Image])

const HandleDeletePic = async () => {
  try {
    
    await updateDoc(doc(db, "group", "z63TKBszLhvBTAmtvfAq"), {
          groupimg:""
    });
    
    const desertRef = ref(storage, "group/group-pic");
    await deleteObject(desertRef);
    toast("Deleted");
  } catch (error) {
    toast(error.message);
  } finally {
    setIsDeleteProfile(false);
  }
}


  return (
    <>
      {isEditGroup ? (
        <>
          <div className="justify-center  items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-50 outline-none focus:outline-none">
            <div className="relative w-[600px]  my-6 mx-auto max-w-4xl">
              {/*content*/}
              <div className="border-0  rounded-lg shadow-lg relative flex flex-col w-full bg-white outline-none focus:outline-none">
                {/*header*/}
                <div className="flex items-start justify-between pr-3 pt-3">
                  <button
                    className="p-1 ml-auto bg-transparent border-0 text-black  float-right text-xl leading-none font-semibold outline-none focus:outline-none"
                    onClick={() => setEditGroup(false)}
                  >
                    <IoMdClose color="#858585" />
                  </button>
                </div>
                {/*body*/}
                <div className="relative p-6  flex flex-col items-center">
                  <h3 className="font-semibold text-[24px] leading-[29px] mb-3 capitalize">
                    Edit Group
                  </h3>
                  <label
                    htmlFor="file"
                    className="w-[88px] mb-3 h-[88px] text-center  relative cursor-pointer"
                  >
                    {
                      GroupName.groupimg?(
                        <img
                        src={preview?preview:GroupName.groupimg}
                        className="w-full h-full rounded-full"
                        alt=""
                        srcset=""
                      />
                      ):(
                        <img
                        src={preview?preview:"noprofile.png"}
                        className="w-full h-full rounded-full"
                        alt=""
                        srcset=""
                      />
                      )
                    }
                  
                    <img
                      src="/upload-img.png"
                      className="absolute -right-2 bottom-0  w-8"
                      alt=""
                      srcset=""
                    />
                    <input
                      type="file"
                      onChange={(e) => setImage(e.target.files[0])}
                      className="hidden"
                      id="file"
                    />
                    <button onClick={HandleDeletePic} className="bg-transparent text-[#FF3B30] font-medium text-[15px] mt-2">
                      Remove
                    </button>
                  </label>

                  <div className="w-full mt-5">
                    <form onSubmit={(e) => UpdateGroup(e)} className="w-full">
                      <div className="mb-3">
                        <label class=" text-[13px] mb-1 font-semibold leading-[16.94px] ">
                          Name
                        </label>
                        <input
                          type="text"
                          id="base-input"
                          value={groupVal}
                          onChange={(e) => setGroupVal(e.target.value)}
                          className="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]  "
                          required
                          placeholder="JB Sittner Trucking LLC"
                        />
                      </div>
                      <div>
                        <button
                          type="submit"
                          class="text-white bg-[#0A8A33]  rounded-lg  w-full mt-3 h-[50px]  px-5 py-2.5 text-center"
                        >
                          Update
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="opacity-25 fixed inset-0 z-40 bg-black"></div>
        </>
      ) : null}
    </>
  );
}
